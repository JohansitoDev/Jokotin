package compiler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeServesAndStoresJSONRecords(t *testing.T) {
	source := `api get "/users" do
  users = db.all("users")
  return users json
end

api post "/users" do
  user = req.body
  db.insert("users", user)
  return "User created" status 201
end
`
	program, err := parseRuntimeProgram(source)
	if err != nil {
		t.Fatal(err)
	}
	handler := program.handler()

	createRequest := httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(`{"name":"Ada"}`))
	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusCreated || createResponse.Body.String() != "User created" {
		t.Fatalf("unexpected create response: %d %q", createResponse.Code, createResponse.Body.String())
	}

	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, httptest.NewRequest(http.MethodGet, "/users", nil))
	if listResponse.Code != http.StatusOK {
		t.Fatalf("unexpected list status: %d", listResponse.Code)
	}
	var users []map[string]interface{}
	if err := json.Unmarshal(listResponse.Body.Bytes(), &users); err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0]["name"] != "Ada" {
		t.Fatalf("unexpected users response: %#v", users)
	}
}

func TestRuntimeRejectsMalformedJSONAndUnsupportedStatements(t *testing.T) {
	program, err := parseRuntimeProgram(`api post "/users" do
  user = req.body
  db.insert("users", user)
  return "created" status 201
end
`)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	program.handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/users", strings.NewReader("{")))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected malformed JSON to return 400, got %d", response.Code)
	}

	_, err = parseRuntimeProgram("api get \"/\" do\n  unknown syntax\nend\n")
	if err == nil || !strings.Contains(err.Error(), "unsupported route statement") {
		t.Fatalf("expected unsupported statement error, got %v", err)
	}
}

func TestRuntimePasswordHashesAndJWT(t *testing.T) {
	passwordHash, err := makePasswordHash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !checkPasswordHash("correct horse battery staple", passwordHash) {
		t.Fatal("correct password did not match its stored hash")
	}
	if checkPasswordHash("wrong password", passwordHash) {
		t.Fatal("incorrect password matched its stored hash")
	}

	secret := []byte("a test-only signing secret with enough bytes")
	now := time.Unix(1_800_000_000, 0)
	token, err := createJWT("user-123", secret, now)
	if err != nil {
		t.Fatal(err)
	}
	claims := verifyJWT("Bearer "+token, secret, now.Add(time.Minute))
	if claims == nil || claims["sub"] != "user-123" {
		t.Fatalf("valid JWT did not return its claims: %#v", claims)
	}
	if verifyJWT(token, []byte("a different test-only secret with enough bytes"), now) != nil {
		t.Fatal("JWT validated with the wrong secret")
	}
	if verifyJWT(token, secret, now.Add(2*time.Hour)) != nil {
		t.Fatal("expired JWT was accepted")
	}
}

func TestRuntimeRegisterLoginAndProtectedRoute(t *testing.T) {
	source := `api post "/register" do
	  existing = db.find("users", email: req.body.email)
	  if existing
	    return { error: "already registered" } status 409
	  end
	  user = req.body
	  user.id = uuid.generate()
	  user._password_hash = hash.make(user.password)
	  user.password = nil
	  db.insert("users", user)
	  return { message: "created" } status 201
	end

	api post "/login" do
	  user = db.find("users", email: req.body.email)
	  if user and hash.check(req.body.password, user._password_hash)
    token = jwt.create(user.id)
    return { token: token } json
  else
    return { error: "invalid credentials" } status 401
  end
end

api get "/users" do
  users = db.all("users")
  return users json
end

api get "/profile" do
  claims = jwt.verify(req.headers.authorization)
  if claims
    return claims json
  else
    return { error: "unauthorized" } status 401
  end
end
`
	program, err := parseRuntimeProgram(source)
	if err != nil {
		t.Fatal(err)
	}
	program.jwtSecret = []byte("a test-only signing secret with enough bytes")
	handler := program.handler()

	register := httptest.NewRecorder()
	handler.ServeHTTP(register, httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(
		`{"email":"ada@example.test","password":"correct horse battery staple"}`,
	)))
	if register.Code != http.StatusCreated {
		t.Fatalf("registration failed: %d %s", register.Code, register.Body.String())
	}
	usersResponse := httptest.NewRecorder()
	handler.ServeHTTP(usersResponse, httptest.NewRequest(http.MethodGet, "/users", nil))
	if strings.Contains(usersResponse.Body.String(), "correct horse battery staple") ||
		strings.Contains(usersResponse.Body.String(), "_password_hash") ||
		strings.Contains(usersResponse.Body.String(), `"password"`) {
		t.Fatalf("public endpoint leaked password credentials: %s", usersResponse.Body.String())
	}
	duplicate := httptest.NewRecorder()
	handler.ServeHTTP(duplicate, httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(
		`{"email":"ada@example.test","password":"another-password"}`,
	)))
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate email should be rejected, got %d: %s", duplicate.Code, duplicate.Body.String())
	}

	login := httptest.NewRecorder()
	handler.ServeHTTP(login, httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(
		`{"email":"ada@example.test","password":"correct horse battery staple"}`,
	)))
	if login.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", login.Code, login.Body.String())
	}
	var response map[string]string
	if err := json.Unmarshal(login.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["token"] == "" {
		t.Fatal("login response did not contain a JWT")
	}

	profileRequest := httptest.NewRequest(http.MethodGet, "/profile", nil)
	profileRequest.Header.Set("Authorization", "Bearer "+response["token"])
	profile := httptest.NewRecorder()
	handler.ServeHTTP(profile, profileRequest)
	if profile.Code != http.StatusOK {
		t.Fatalf("valid token was not accepted: %d %s", profile.Code, profile.Body.String())
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(profile.Body.Bytes(), &claims); err != nil {
		t.Fatal(err)
	}
	subject, ok := claims["sub"].(string)
	if !ok || len(subject) != 36 {
		t.Fatalf("JWT did not contain a generated account ID: %#v", claims["sub"])
	}

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/profile", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("missing JWT should be rejected, got %d", unauthorized.Code)
	}
}

func TestRuntimeAcceptsStandardAndCustomHTTPMethodsAndPathParameters(t *testing.T) {
	program, err := parseRuntimeProgram(`api delete "/users/:id" do
  return { id: req.params.id, method: req.method } json
end

api options "/users" do
  return "ok" status 200
end
`)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	program.handler().ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/users/42", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"id":"42"`) {
		t.Fatalf("route parameter was not available: %d %s", response.Code, response.Body.String())
	}
	options := httptest.NewRecorder()
	program.handler().ServeHTTP(options, httptest.NewRequest(http.MethodOptions, "/users", nil))
	if options.Code != http.StatusOK {
		t.Fatalf("OPTIONS route was not served: %d %s", options.Code, options.Body.String())
	}
}

func TestRuntimeUpdatesAndDeletesRecordsByPathID(t *testing.T) {
	program, err := parseRuntimeProgram(`api post "/items" do
  item = req.body
  db.insert("items", item)
  return "created" status 201
end

api put "/items/:id" do
  item = req.body
  db.update("items", req.params.id, item)
  return "updated" status 200
end

api delete "/items/:id" do
  db.delete("items", req.params.id)
  return "deleted" status 200
end

api get "/items" do
  items = db.all("items")
  return items json
end
`)
	if err != nil {
		t.Fatal(err)
	}
	handler := program.handler()
	for _, testCase := range []struct {
		method string
		path   string
		body   string
		code   int
	}{
		{http.MethodPost, "/items", `{"id":"7","name":"old"}`, http.StatusCreated},
		{http.MethodPut, "/items/7", `{"id":"7","name":"new"}`, http.StatusOK},
		{http.MethodDelete, "/items/7", "", http.StatusOK},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(testCase.method, testCase.path, strings.NewReader(testCase.body)))
		if response.Code != testCase.code {
			t.Fatalf("%s %s: expected %d, got %d: %s", testCase.method, testCase.path, testCase.code, response.Code, response.Body.String())
		}
	}
	list := httptest.NewRecorder()
	handler.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/items", nil))
	var items []map[string]interface{}
	if err := json.Unmarshal(list.Body.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("delete left records behind: %#v", items)
	}
}

func TestExampleBackendParsesWithJWTAndAllRoutes(t *testing.T) {
	source, err := LoadJokFile(filepath.Join("..", "examples", "main.jok"))
	if err != nil {
		t.Fatal(err)
	}
	program, err := parseRuntimeProgram(source)
	if err != nil {
		t.Fatal(err)
	}
	if !program.usesJWT {
		t.Fatal("example backend must require JWT configuration")
	}
	if len(program.routes) < 8 {
		t.Fatalf("expected user CRUD and auth endpoints, got %d routes", len(program.routes))
	}
}

func TestRuntimeServesAutomaticSwaggerUIAndOpenAPISpec(t *testing.T) {
	program, err := parseRuntimeProgram(`api get "/users/:id" do
  user = db.find("users", id: req.params.id)
  claims = jwt.verify(req.headers.authorization)
  if claims
    return user json
  else
    return { error: "Unauthorized" } status 401
  end
end
`)
	if err != nil {
		t.Fatal(err)
	}
	handler := program.handler()

	specResponse := httptest.NewRecorder()
	handler.ServeHTTP(specResponse, httptest.NewRequest(http.MethodGet, "/swagger.json", nil))
	if specResponse.Code != http.StatusOK {
		t.Fatalf("OpenAPI spec returned %d", specResponse.Code)
	}
	var document map[string]interface{}
	if err := json.Unmarshal(specResponse.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document["openapi"] != "3.0.3" {
		t.Fatalf("unexpected OpenAPI version: %#v", document["openapi"])
	}
	paths := document["paths"].(map[string]interface{})
	userPath := paths["/users/{id}"].(map[string]interface{})
	get := userPath["get"].(map[string]interface{})
	if _, ok := get["security"]; !ok {
		t.Fatal("JWT-protected route missing bearer security metadata")
	}
	parameters := get["parameters"].([]interface{})
	if len(parameters) != 1 || parameters[0].(map[string]interface{})["name"] != "id" {
		t.Fatalf("path parameter was not documented: %#v", parameters)
	}

	docsResponse := httptest.NewRecorder()
	handler.ServeHTTP(docsResponse, httptest.NewRequest(http.MethodGet, "/docs", nil))
	if docsResponse.Code != http.StatusOK || !strings.Contains(docsResponse.Body.String(), "SwaggerUIBundle") {
		t.Fatalf("Swagger UI was not served automatically: %d", docsResponse.Code)
	}
}

func TestRuntimeSQLiteDatabasePersistsRecordsAcrossConnections(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "data", "jokotin.db")
	db, err := openRuntimeDB("sqlite:"+databasePath, "")
	if err != nil {
		t.Fatal(err)
	}
	record := map[string]interface{}{"id": "user-1", "email": "ada@example.test"}
	if err := db.insert("users", record); err != nil {
		t.Fatal(err)
	}
	if err := db.sqlDB.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = openRuntimeDB("sqlite:"+databasePath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.sqlDB.Close()
	found, err := db.find("users", "email", "ada@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if found["id"] != "user-1" {
		t.Fatalf("SQLite record was not persisted: %#v", found)
	}
	if updated, err := db.update("users", "id", "user-1", map[string]interface{}{"id": "user-1", "email": "new@example.test"}); err != nil || !updated {
		t.Fatalf("SQLite update failed: updated=%v err=%v", updated, err)
	}
	if deleted, err := db.delete("users", "id", "user-1"); err != nil || !deleted {
		t.Fatalf("SQLite delete failed: deleted=%v err=%v", deleted, err)
	}
	records, err := db.all("users")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("SQLite record remains after delete: %#v", records)
	}
}

func TestRuntimeSQLiteDatabasePathIsRelativeToEntryDirectory(t *testing.T) {
	baseDirectory := t.TempDir()
	db, err := openRuntimeDB("sqlite:./data/api.db", baseDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(baseDirectory, "data", "api.db")); err != nil {
		t.Fatalf("SQLite database was not created next to the Jokotin project: %v", err)
	}
}

func TestRuntimeParsesDatabaseEnvironmentAndReservesSwaggerPaths(t *testing.T) {
	program, err := parseRuntimeProgram(`db connect env "DATABASE_URL"
api get "/users" do
  return [] json
end
`)
	if err != nil {
		t.Fatal(err)
	}
	if program.databaseEnv != "DATABASE_URL" {
		t.Fatalf("database environment variable was not parsed: %q", program.databaseEnv)
	}
	if _, err := parseRuntimeProgram(`api get "/docs" do
  return "custom" status 200
end
`); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("expected automatic docs path to be reserved, got %v", err)
	}
}
