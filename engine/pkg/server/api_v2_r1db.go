// Copyright 2026 Ratio1
// Licensed under the Apache License, Version 2.0 (the "License").
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/cockroachdb/cockroach/pkg/security/username"
	"github.com/cockroachdb/cockroach/pkg/server/serverpb"
	"github.com/cockroachdb/cockroach/pkg/sql/isql"
	"github.com/cockroachdb/cockroach/pkg/sql/lexbase"
	"github.com/cockroachdb/cockroach/pkg/sql/pgwire/pgcode"
	"github.com/cockroachdb/cockroach/pkg/sql/pgwire/pgerror"
	"github.com/cockroachdb/cockroach/pkg/sql/sem/tree"
	"github.com/cockroachdb/cockroach/pkg/sql/sessiondata"
	"github.com/cockroachdb/cockroach/pkg/util/log"
	"github.com/cockroachdb/errors"
)

const (
	r1dbMaxManagementRequestBytes = 1 << 20
	r1dbVersionPath               = "/usr/share/r1db/VERSION"
)

// The console uses this small, explicit API for operations that the generic
// SQL endpoint intentionally does not expose (for example, CREATE USER and
// GRANT). Keeping the privilege vocabulary here prevents browser input from
// becoming arbitrary SQL.
type r1dbAccessRequest struct {
	Username  string   `json:"username"`
	Database  string   `json:"database,omitempty"`
	Databases []string `json:"databases,omitempty"`
	Table     string   `json:"table,omitempty"`
	Scope     string   `json:"scope"`
	Preset    string   `json:"preset"`
	Action    string   `json:"action"`
}

type r1dbCreateDatabaseRequest struct {
	Name string `json:"name"`
}

type r1dbCreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type r1dbDeleteUserRequest struct {
	Username string `json:"username"`
}

type r1dbCreateTableColumn struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Nullable   bool   `json:"nullable"`
	PrimaryKey bool   `json:"primary_key"`
	Default    string `json:"default,omitempty"`
}

type r1dbCreateTableRequest struct {
	Database string                  `json:"database"`
	Schema   string                  `json:"schema,omitempty"`
	Name     string                  `json:"name"`
	Columns  []r1dbCreateTableColumn `json:"columns"`
}

type r1dbAccessResponse struct {
	Username   string   `json:"username"`
	Database   string   `json:"database"`
	Table      string   `json:"table,omitempty"`
	Scope      string   `json:"scope"`
	Privileges []string `json:"privileges"`
}

type r1dbCapabilitiesResponse struct {
	CanViewAccess     bool `json:"can_view_access"`
	CanCreateUser     bool `json:"can_create_user"`
	CanCreateDatabase bool `json:"can_create_database"`
}

type r1dbVersionResponse struct {
	Version string `json:"version"`
}

type r1dbNodeConfigResponse struct {
	ConfiguredNodeCount int `json:"configured_node_count"`
}

type r1dbDatabasesResponse struct {
	Databases []string `json:"databases"`
	Next      int      `json:"next,omitempty"`
}

type r1dbPermission struct {
	Database   string   `json:"database"`
	Schema     string   `json:"schema,omitempty"`
	Table      string   `json:"table,omitempty"`
	Scope      string   `json:"scope"`
	Privileges []string `json:"privileges"`
	Source     string   `json:"source"`
	SourceRole string   `json:"source_role,omitempty"`
	Grantable  bool     `json:"grantable"`
}

type r1dbPermissionsResponse struct {
	Username    string           `json:"username"`
	Permissions []r1dbPermission `json:"permissions"`
	Next        int              `json:"next,omitempty"`
}

type r1dbPermissionKey struct {
	database   string
	schema     string
	table      string
	scope      string
	source     string
	sourceRole string
}

type r1dbPermissionAggregate struct {
	r1dbPermission
	privilegeSet map[string]struct{}
}

func r1dbMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	http.Error(w, "only "+method+" supported", http.StatusMethodNotAllowed)
	return false
}

func decodeR1DBJSON(w http.ResponseWriter, r *http.Request, payload interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, r1dbMaxManagementRequestBytes)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(payload); err != nil {
		return errors.Wrap(err, "invalid JSON request")
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain one JSON object")
		}
		return errors.Wrap(err, "invalid JSON request")
	}
	return nil
}

func r1dbRequestError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusBadRequest)
}

func r1dbExecutionError(ctx context.Context, w http.ResponseWriter, err error) {
	log.ErrorfDepth(ctx, 1, "%s", err)
	code := http.StatusBadRequest
	if pgerror.GetPGCode(err) == pgcode.InsufficientPrivilege {
		code = http.StatusForbidden
	}
	http.Error(w, err.Error(), code)
}

func r1dbDatabaseName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", errors.New("database name is required")
	}
	return name, nil
}

func r1dbIdentifier(raw, label string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", errors.Newf("%s is required", label)
	}
	if strings.ContainsRune(name, '\x00') {
		return "", errors.Newf("%s contains an invalid character", label)
	}
	return name, nil
}

func r1dbTableColumnType(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "bool", "boolean":
		return "BOOL", nil
	case "int", "integer":
		return "INT", nil
	case "int8", "bigint":
		return "INT8", nil
	case "float", "double":
		return "FLOAT", nil
	case "decimal", "numeric":
		return "DECIMAL", nil
	case "string", "text":
		return "STRING", nil
	case "bytes":
		return "BYTES", nil
	case "date":
		return "DATE", nil
	case "timestamp":
		return "TIMESTAMP", nil
	case "timestamptz":
		return "TIMESTAMPTZ", nil
	case "uuid":
		return "UUID", nil
	case "jsonb", "json":
		return "JSONB", nil
	default:
		return "", errors.Newf("unsupported column type %q", raw)
	}
}

func r1dbTableColumnDefault(raw, columnType string) (string, error) {
	choice := strings.ToLower(strings.TrimSpace(raw))
	switch choice {
	case "", "none":
		return "", nil
	case "uuid":
		if columnType != "UUID" {
			return "", errors.New("generated UUID defaults require UUID columns")
		}
		return "gen_random_uuid()", nil
	case "timestamp":
		if columnType != "TIMESTAMP" && columnType != "TIMESTAMPTZ" {
			return "", errors.New("current timestamp defaults require timestamp columns")
		}
		return "current_timestamp()", nil
	case "date":
		if columnType != "DATE" {
			return "", errors.New("current date defaults require DATE columns")
		}
		return "current_date()", nil
	case "zero":
		switch columnType {
		case "INT", "INT8", "FLOAT", "DECIMAL":
			return "0", nil
		default:
			return "", errors.New("zero defaults require numeric columns")
		}
	case "true", "false":
		if columnType != "BOOL" {
			return "", errors.New("boolean defaults require BOOL columns")
		}
		return choice, nil
	default:
		return "", errors.Newf("unsupported column default %q", raw)
	}
}

func r1dbCreateTableSQL(req r1dbCreateTableRequest) (string, string, string, string, error) {
	database, err := r1dbDatabaseName(req.Database)
	if err != nil {
		return "", "", "", "", err
	}
	schemaName := strings.TrimSpace(req.Schema)
	if schemaName == "" {
		schemaName = "public"
	}
	schema, err := r1dbIdentifier(schemaName, "schema")
	if err != nil {
		return "", "", "", "", err
	}
	table, err := r1dbIdentifier(req.Name, "table name")
	if err != nil {
		return "", "", "", "", err
	}
	if len(req.Columns) == 0 {
		return "", "", "", "", errors.New("at least one column is required")
	}
	if len(req.Columns) > 128 {
		return "", "", "", "", errors.New("a table cannot have more than 128 columns")
	}

	definitions := make([]string, 0, len(req.Columns)+1)
	primaryKeys := make([]string, 0)
	seenColumns := make(map[string]struct{}, len(req.Columns))
	for _, column := range req.Columns {
		columnName, err := r1dbIdentifier(column.Name, "column name")
		if err != nil {
			return "", "", "", "", err
		}
		columnKey := strings.ToLower(columnName)
		if _, exists := seenColumns[columnKey]; exists {
			return "", "", "", "", errors.Newf("duplicate column name %q", columnName)
		}
		seenColumns[columnKey] = struct{}{}
		columnType, err := r1dbTableColumnType(column.Type)
		if err != nil {
			return "", "", "", "", err
		}
		defaultExpr, err := r1dbTableColumnDefault(column.Default, columnType)
		if err != nil {
			return "", "", "", "", err
		}

		definition := tree.NameStringP(&columnName) + " " + columnType
		if !column.Nullable || column.PrimaryKey {
			definition += " NOT NULL"
		}
		if defaultExpr != "" {
			definition += " DEFAULT " + defaultExpr
		}
		definitions = append(definitions, definition)
		if column.PrimaryKey {
			primaryKeys = append(primaryKeys, tree.NameStringP(&columnName))
		}
	}
	if len(primaryKeys) > 0 {
		definitions = append(definitions, "PRIMARY KEY ("+strings.Join(primaryKeys, ", ")+")")
	}

	qualifiedTable := strings.Join([]string{
		tree.NameStringP(&database),
		tree.NameStringP(&schema),
		tree.NameStringP(&table),
	}, ".")
	return database, schema, table, fmt.Sprintf("CREATE TABLE %s (%s)", qualifiedTable, strings.Join(definitions, ", ")), nil
}

func r1dbAccessDatabases(req r1dbAccessRequest) ([]string, error) {
	rawDatabases := req.Databases
	if len(rawDatabases) == 0 {
		rawDatabases = []string{req.Database}
	}

	databases := make([]string, 0, len(rawDatabases))
	seen := make(map[string]struct{}, len(rawDatabases))
	for _, raw := range rawDatabases {
		database, err := r1dbDatabaseName(raw)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[database]; exists {
			continue
		}
		seen[database] = struct{}{}
		databases = append(databases, database)
	}
	if len(databases) == 0 {
		return nil, errors.New("at least one database is required")
	}
	return databases, nil
}

func r1dbCreateUsername(raw string) (username.SQLUsername, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return username.SQLUsername{}, errors.New("username is required")
	}
	user, err := username.MakeSQLUsernameFromUserInput(name, username.PurposeCreation)
	if err != nil {
		return username.SQLUsername{}, err
	}
	if user.IsReserved() {
		return username.SQLUsername{}, errors.Newf("role name %q is reserved", user.Normalized())
	}
	return user, nil
}

func r1dbExistingUsername(raw string) (username.SQLUsername, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return username.SQLUsername{}, errors.New("username is required")
	}
	user, _ := username.MakeSQLUsernameFromUserInput(name, username.PurposeValidation)
	if user.IsReserved() {
		return username.SQLUsername{}, errors.Newf("role name %q cannot be managed", user.Normalized())
	}
	return user, nil
}

func r1dbPermissionUsername(raw string) (username.SQLUsername, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return username.SQLUsername{}, errors.New("username is required")
	}
	user, err := username.MakeSQLUsernameFromUserInput(name, username.PurposeValidation)
	if err != nil {
		return username.SQLUsername{}, err
	}
	return user, nil
}

func r1dbCapabilityBool(row tree.Datums, index int) (bool, error) {
	if index < 0 || index >= len(row) {
		return false, errors.Errorf("capability query returned %d columns", len(row))
	}
	value, ok := tree.AsDBool(row[index])
	if !ok {
		return false, errors.Errorf("capability query returned %T at column %d", row[index], index)
	}
	return bool(value), nil
}

func (a *apiV2Server) r1dbCapabilities(w http.ResponseWriter, r *http.Request) {
	if !r1dbMethod(w, r, http.MethodGet) {
		return
	}
	ctx := a.sqlServer.AnnotateCtx(r.Context())
	actor := userFromHTTPAuthInfoContext(ctx)
	row, err := a.sqlServer.internalExecutor.QueryRowEx(
		ctx, "r1db-capabilities", nil,
		sessiondata.InternalExecutorOverride{User: actor},
		"SELECT crdb_internal.is_admin(), crdb_internal.has_role_option('CREATEDB')",
	)
	if err != nil {
		r1dbExecutionError(ctx, w, err)
		return
	}
	if len(row) != 2 {
		r1dbExecutionError(ctx, w, errors.Errorf("capability query returned %d columns", len(row)))
		return
	}
	isAdmin, err := r1dbCapabilityBool(row, 0)
	if err != nil {
		r1dbExecutionError(ctx, w, err)
		return
	}
	hasCreateDatabase, err := r1dbCapabilityBool(row, 1)
	if err != nil {
		r1dbExecutionError(ctx, w, err)
		return
	}
	writeJSONResponse(ctx, w, http.StatusOK, r1dbCapabilitiesResponse{
		CanViewAccess:     isAdmin,
		CanCreateUser:     isAdmin,
		CanCreateDatabase: isAdmin || hasCreateDatabase,
	})
}

func (a *apiV2Server) r1dbVersion(w http.ResponseWriter, r *http.Request) {
	if !r1dbMethod(w, r, http.MethodGet) {
		return
	}
	ctx := a.sqlServer.AnnotateCtx(r.Context())
	contents, err := os.ReadFile(r1dbVersionPath)
	if err != nil {
		apiV2InternalError(ctx, errors.Wrap(err, "read R1DB image version"), w)
		return
	}
	version := strings.TrimSpace(string(contents))
	if version == "" {
		apiV2InternalError(ctx, errors.New("R1DB image version is empty"), w)
		return
	}
	writeJSONResponse(ctx, w, http.StatusOK, r1dbVersionResponse{Version: version})
}

// GET /api/v2/r1db/node-config/ is admin-only and returns the configured
// deployment target as {"configured_node_count": N}; an unset/invalid target
// returns 503. CRDB_NODE_ID is not a database node ID.
func (a *apiV2Server) r1dbNodeConfig(w http.ResponseWriter, r *http.Request) {
	if !r1dbMethod(w, r, http.MethodGet) {
		return
	}
	count, err := strconv.Atoi(strings.TrimSpace(os.Getenv("CRDB_NODE_COUNT")))
	if err != nil || count < 1 {
		http.Error(w, "configured node count is unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSONResponse(r.Context(), w, http.StatusOK, r1dbNodeConfigResponse{ConfiguredNodeCount: count})
}

func (a *apiV2Server) r1dbUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.listUsers(w, r)
	case http.MethodPost:
		a.r1dbCreateUser(w, r)
	case http.MethodDelete:
		a.r1dbDeleteUser(w, r)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "only GET, POST and DELETE supported", http.StatusMethodNotAllowed)
	}
}

func (a *apiV2Server) r1dbDatabases(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.r1dbListDatabases(w, r)
	case http.MethodPost:
		a.r1dbCreateDatabase(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "only GET and POST supported", http.StatusMethodNotAllowed)
	}
}

func (a *apiV2Server) r1dbListDatabases(w http.ResponseWriter, r *http.Request) {
	if !r1dbMethod(w, r, http.MethodGet) {
		return
	}
	ctx := a.sqlServer.AnnotateCtx(r.Context())
	actor := userFromHTTPAuthInfoContext(ctx)
	it, err := a.sqlServer.internalExecutor.QueryIteratorEx(
		ctx, "r1db-list-databases", nil,
		sessiondata.InternalExecutorOverride{User: actor},
		"SELECT database_name FROM [SHOW DATABASES] WHERE has_database_privilege(database_name, 'CONNECT') ORDER BY database_name",
	)
	if err != nil {
		r1dbExecutionError(ctx, w, err)
		return
	}
	defer func() { _ = it.Close() }()

	databases := make([]string, 0)
	ok, err := it.Next(ctx)
	for ; ok; ok, err = it.Next(ctx) {
		row := it.Cur()
		if len(row) == 0 {
			r1dbExecutionError(ctx, w, errors.New("database listing returned an empty row"))
			return
		}
		database, ok := tree.AsDString(row[0])
		if !ok {
			r1dbExecutionError(ctx, w, errors.Errorf("database listing returned %T for the database name", row[0]))
			return
		}
		databases = append(databases, string(database))
	}
	if err != nil {
		r1dbExecutionError(ctx, w, err)
		return
	}

	limit, offset := getSimplePaginationValues(r)
	visible, next := simplePaginate(databases, limit, offset)
	writeJSONResponse(ctx, w, http.StatusOK, r1dbDatabasesResponse{
		Databases: visible.([]string),
		Next:      next,
	})
}

func (a *apiV2Server) r1dbListDatabaseTables(w http.ResponseWriter, r *http.Request) {
	if !r1dbMethod(w, r, http.MethodGet) {
		return
	}
	database, err := r1dbDatabaseName(r.URL.Query().Get("database"))
	if err != nil {
		r1dbRequestError(w, err)
		return
	}
	ctx := a.sqlServer.AnnotateCtx(r.Context())
	actor := userFromHTTPAuthInfoContext(ctx)
	limit, offset := getSimplePaginationValues(r)
	tables, err := a.admin.getDatabaseTables(ctx, &serverpb.DatabaseDetailsRequest{Database: database}, actor, limit, offset)
	if err != nil {
		r1dbExecutionError(ctx, w, err)
		return
	}
	response := databaseTablesResponse{TableNames: tables}
	if limit > 0 && len(tables) >= limit {
		response.Next = offset + len(tables)
	}
	writeJSONResponse(ctx, w, http.StatusOK, response)
}

func (a *apiV2Server) r1dbCreateDatabase(w http.ResponseWriter, r *http.Request) {
	if !r1dbMethod(w, r, http.MethodPost) {
		return
	}
	var req r1dbCreateDatabaseRequest
	if err := decodeR1DBJSON(w, r, &req); err != nil {
		r1dbRequestError(w, err)
		return
	}
	database, err := r1dbDatabaseName(req.Name)
	if err != nil {
		r1dbRequestError(w, err)
		return
	}

	ctx := a.sqlServer.AnnotateCtx(r.Context())
	actor := userFromHTTPAuthInfoContext(ctx)
	quotedDatabase := tree.NameStringP(&database)
	actorName := actor.Normalized()
	quotedActor := tree.NameStringP(&actorName)
	if err := a.sqlServer.internalDB.Txn(ctx, func(ctx context.Context, txn isql.Txn) error {
		statements := []struct {
			query string
			user  username.SQLUsername
		}{
			{query: "CREATE DATABASE " + quotedDatabase, user: actor},
			{query: "REVOKE CONNECT ON DATABASE " + quotedDatabase + " FROM public", user: actor},
			// The new public schema is admin-owned, even when a CREATEDB user owns the database.
			{query: "REVOKE CREATE ON SCHEMA " + quotedDatabase + ".public FROM public", user: username.RootUserName()},
			{query: "GRANT CREATE ON SCHEMA " + quotedDatabase + ".public TO " + quotedActor, user: username.RootUserName()},
		}
		for _, statement := range statements {
			if _, err := txn.ExecEx(
				ctx, "r1db-create-private-database", txn.KV(),
				sessiondata.InternalExecutorOverride{User: statement.user}, statement.query,
			); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		r1dbExecutionError(ctx, w, err)
		return
	}
	writeJSONResponse(ctx, w, http.StatusCreated, struct {
		Database string `json:"database"`
	}{Database: database})
}

func (a *apiV2Server) r1dbCreateTable(w http.ResponseWriter, r *http.Request) {
	if !r1dbMethod(w, r, http.MethodPost) {
		return
	}
	var req r1dbCreateTableRequest
	if err := decodeR1DBJSON(w, r, &req); err != nil {
		r1dbRequestError(w, err)
		return
	}
	database, schema, table, query, err := r1dbCreateTableSQL(req)
	if err != nil {
		r1dbRequestError(w, err)
		return
	}

	ctx := a.sqlServer.AnnotateCtx(r.Context())
	actor := userFromHTTPAuthInfoContext(ctx)
	if _, err := a.sqlServer.internalExecutor.ExecEx(
		ctx, "r1db-create-table", nil,
		sessiondata.InternalExecutorOverride{User: actor, Database: database}, query,
	); err != nil {
		r1dbExecutionError(ctx, w, err)
		return
	}
	writeJSONResponse(ctx, w, http.StatusCreated, struct {
		Database string `json:"database"`
		Schema   string `json:"schema"`
		Table    string `json:"table"`
	}{Database: database, Schema: schema, Table: table})
}

func (a *apiV2Server) r1dbCreateUser(w http.ResponseWriter, r *http.Request) {
	if !r1dbMethod(w, r, http.MethodPost) {
		return
	}
	var req r1dbCreateUserRequest
	if err := decodeR1DBJSON(w, r, &req); err != nil {
		r1dbRequestError(w, err)
		return
	}
	user, err := r1dbCreateUsername(req.Username)
	if err != nil {
		r1dbRequestError(w, err)
		return
	}
	if req.Password == "" {
		r1dbRequestError(w, errors.New("password is required"))
		return
	}

	ctx := a.sqlServer.AnnotateCtx(r.Context())
	actor := userFromHTTPAuthInfoContext(ctx)
	userName := user.Normalized()
	// CREATE USER audit events log placeholder values, including password parameters.
	query := fmt.Sprintf("CREATE USER %s WITH PASSWORD %s", tree.NameStringP(&userName), lexbase.EscapeSQLString(req.Password))
	if _, err := a.sqlServer.internalExecutor.ExecEx(
		ctx, "r1db-create-user", nil,
		sessiondata.InternalExecutorOverride{User: actor}, query,
	); err != nil {
		r1dbExecutionError(ctx, w, err)
		return
	}
	writeJSONResponse(ctx, w, http.StatusCreated, struct {
		Username string `json:"username"`
	}{Username: userName})
}

func (a *apiV2Server) r1dbDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !r1dbMethod(w, r, http.MethodDelete) {
		return
	}
	var req r1dbDeleteUserRequest
	if err := decodeR1DBJSON(w, r, &req); err != nil {
		r1dbRequestError(w, err)
		return
	}
	user, err := r1dbExistingUsername(req.Username)
	if err != nil {
		r1dbRequestError(w, err)
		return
	}
	ctx := a.sqlServer.AnnotateCtx(r.Context())
	actor := userFromHTTPAuthInfoContext(ctx)
	userName := user.Normalized()
	if user.IsRootUser() || user.IsAdminRole() {
		r1dbRequestError(w, errors.New("cannot delete a protected user"))
		return
	}
	if userName == actor.Normalized() {
		r1dbRequestError(w, errors.New("cannot delete the current user"))
		return
	}
	query := fmt.Sprintf("DROP USER %s", tree.NameStringP(&userName))
	if _, err := a.sqlServer.internalExecutor.ExecEx(
		ctx, "r1db-delete-user", nil,
		sessiondata.InternalExecutorOverride{User: actor}, query,
	); err != nil {
		r1dbExecutionError(ctx, w, err)
		return
	}
	writeJSONResponse(ctx, w, http.StatusOK, struct {
		Username string `json:"username"`
	}{Username: userName})
}

func r1dbAccessSQL(req r1dbAccessRequest, target username.SQLUsername) (string, error) {
	database, err := r1dbDatabaseName(req.Database)
	if err != nil {
		return "", err
	}
	scope := strings.ToLower(strings.TrimSpace(req.Scope))
	if scope != "database" && scope != "table" {
		return "", errors.New("scope must be database or table")
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action != "grant" && action != "revoke" {
		return "", errors.New("action must be grant or revoke")
	}
	preset := strings.ToLower(strings.TrimSpace(req.Preset))
	if preset != "viewer" && preset != "editor" {
		return "", errors.New("preset must be viewer or editor")
	}

	object := "DATABASE " + tree.NameStringP(&database)
	privileges := "CONNECT"
	if scope == "table" {
		if strings.TrimSpace(req.Table) == "" {
			return "", errors.New("table is required for table access")
		}
		qualifiedTable, err := getFullyQualifiedTableName(database, req.Table)
		if err != nil {
			return "", errors.Wrap(err, "invalid table name")
		}
		object = "TABLE " + qualifiedTable
		privileges = "SELECT"
		if preset == "editor" {
			privileges = "SELECT, INSERT, UPDATE, DELETE"
		}
	} else if req.Table != "" {
		return "", errors.New("table is only valid for table access")
	} else if preset == "editor" {
		privileges = "CONNECT, CREATE"
	}

	verb := "GRANT"
	roleKeyword := "TO"
	if action == "revoke" {
		verb = "REVOKE"
		roleKeyword = "FROM"
	}
	userName := target.Normalized()
	return fmt.Sprintf("%s %s ON %s %s %s", verb, privileges, object, roleKeyword, tree.NameStringP(&userName)), nil
}

func (a *apiV2Server) r1dbAccess(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.r1dbGetAccess(w, r)
	case http.MethodPost:
		a.r1dbChangeAccess(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "only GET and POST supported", http.StatusMethodNotAllowed)
	}
}

func (a *apiV2Server) r1dbGetAccess(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	database, err := r1dbDatabaseName(query.Get("database"))
	if err != nil {
		r1dbRequestError(w, err)
		return
	}
	target, err := r1dbExistingUsername(query.Get("username"))
	if err != nil {
		r1dbRequestError(w, err)
		return
	}
	table := strings.TrimSpace(query.Get("table"))
	scope := "database"
	showQuery := fmt.Sprintf("SELECT * FROM [SHOW GRANTS ON DATABASE %s]", tree.NameStringP(&database))
	if table != "" {
		scope = "table"
		qualifiedTable, err := getFullyQualifiedTableName(database, table)
		if err != nil {
			r1dbRequestError(w, errors.Wrap(err, "invalid table name"))
			return
		}
		showQuery = fmt.Sprintf("SHOW GRANTS ON TABLE %s", qualifiedTable)
	}

	ctx := a.sqlServer.AnnotateCtx(r.Context())
	actor := userFromHTTPAuthInfoContext(ctx)
	privileges, err := a.r1dbReadGrants(ctx, actor, showQuery, target)
	if err != nil {
		r1dbExecutionError(ctx, w, err)
		return
	}
	writeJSONResponse(ctx, w, http.StatusOK, r1dbAccessResponse{
		Username:   target.Normalized(),
		Database:   database,
		Table:      table,
		Scope:      scope,
		Privileges: privileges,
	})
}

func (a *apiV2Server) r1dbPermissions(w http.ResponseWriter, r *http.Request) {
	if !r1dbMethod(w, r, http.MethodGet) {
		return
	}
	target, err := r1dbPermissionUsername(r.URL.Query().Get("username"))
	if err != nil {
		r1dbRequestError(w, err)
		return
	}

	ctx := a.sqlServer.AnnotateCtx(r.Context())
	actor := userFromHTTPAuthInfoContext(ctx)
	permissions, err := a.r1dbReadPermissions(ctx, actor, target)
	if err != nil {
		r1dbExecutionError(ctx, w, err)
		return
	}

	limit, offset := getSimplePaginationValues(r)
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	if offset > len(permissions) {
		offset = len(permissions)
	}
	end := offset + limit
	if end > len(permissions) {
		end = len(permissions)
	}
	response := r1dbPermissionsResponse{
		Username:    target.Normalized(),
		Permissions: permissions[offset:end],
	}
	if end < len(permissions) {
		response.Next = end
	}
	writeJSONResponse(ctx, w, http.StatusOK, response)
}

func (a *apiV2Server) r1dbReadPermissions(
	ctx context.Context, actor username.SQLUsername, target username.SQLUsername,
) ([]r1dbPermission, error) {
	targetName := target.Normalized()
	query := fmt.Sprintf(`SELECT * FROM [SHOW GRANTS FOR %s, public]
		WHERE object_type IN ('database', 'schema', 'table')
		AND (schema_name IS NULL OR schema_name NOT IN
		('crdb_internal', 'information_schema', 'pg_catalog', 'pg_extension'))`, tree.NameStringP(&targetName))
	databaseIterator, err := a.sqlServer.internalExecutor.QueryIteratorEx(
		ctx, "r1db-list-grant-databases", nil,
		sessiondata.InternalExecutorOverride{User: actor}, "SHOW DATABASES",
	)
	if err != nil {
		return nil, err
	}
	databaseNames := make([]string, 0)
	ok, err := databaseIterator.Next(ctx)
	for ; ok; ok, err = databaseIterator.Next(ctx) {
		row := databaseIterator.Cur()
		if len(row) == 0 {
			return nil, errors.New("SHOW DATABASES returned an empty row")
		}
		databaseDatum, ok := tree.AsDString(row[0])
		if !ok {
			return nil, errors.Errorf("SHOW DATABASES returned %T for the database name", row[0])
		}
		databaseNames = append(databaseNames, string(databaseDatum))
	}
	if err != nil {
		return nil, err
	}
	if err := databaseIterator.Close(); err != nil {
		return nil, err
	}

	grants := make(map[r1dbPermissionKey]*r1dbPermissionAggregate)
	for _, database := range databaseNames {
		it, err := a.sqlServer.internalExecutor.QueryIteratorEx(
			ctx, "r1db-show-user-grants", nil,
			sessiondata.InternalExecutorOverride{User: actor, Database: database}, query,
		)
		if err != nil {
			return nil, err
		}

		scanner := makeResultScanner(it.Types())
		ok, err := it.Next(ctx)
		for ; ok; ok, err = it.Next(ctx) {
			row := it.Cur()
			var databaseName, schemaName, objectName *string
			var objectType, grantee, privilege string
			var grantable bool
			if err := scanner.Scan(row, "database_name", &databaseName); err != nil {
				return nil, err
			}
			if err := scanner.Scan(row, "schema_name", &schemaName); err != nil {
				return nil, err
			}
			if err := scanner.Scan(row, "object_name", &objectName); err != nil {
				return nil, err
			}
			if err := scanner.Scan(row, "object_type", &objectType); err != nil {
				return nil, err
			}
			if err := scanner.Scan(row, "grantee", &grantee); err != nil {
				return nil, err
			}
			if err := scanner.Scan(row, "privilege_type", &privilege); err != nil {
				return nil, err
			}
			if err := scanner.Scan(row, "is_grantable", &grantable); err != nil {
				return nil, err
			}
			if databaseName == nil {
				continue
			}
			scope := strings.ToLower(strings.TrimSpace(objectType))
			if scope != "database" && scope != "schema" && scope != "table" {
				continue
			}
			source := "direct"
			sourceRole := ""
			if !strings.EqualFold(grantee, targetName) {
				if strings.EqualFold(grantee, "public") {
					source = "public"
				} else {
					source = "role"
					sourceRole = grantee
				}
			}
			key := r1dbPermissionKey{
				database:   *databaseName,
				schema:     valueOrEmpty(schemaName),
				table:      valueOrEmpty(objectName),
				scope:      scope,
				source:     source,
				sourceRole: sourceRole,
			}
			aggregate, found := grants[key]
			if !found {
				aggregate = &r1dbPermissionAggregate{
					r1dbPermission: r1dbPermission{
						Database:   key.database,
						Schema:     key.schema,
						Table:      key.table,
						Scope:      key.scope,
						Source:     key.source,
						SourceRole: key.sourceRole,
					},
					privilegeSet: make(map[string]struct{}),
				}
				grants[key] = aggregate
			}
			privilege = strings.ToUpper(strings.TrimSpace(privilege))
			if privilege != "" {
				aggregate.privilegeSet[privilege] = struct{}{}
			}
			aggregate.Grantable = aggregate.Grantable || grantable
		}
		if err != nil {
			_ = it.Close()
			return nil, err
		}
		if err := it.Close(); err != nil {
			return nil, err
		}
	}

	permissions := make([]r1dbPermission, 0, len(grants))
	for _, aggregate := range grants {
		aggregate.Privileges = make([]string, 0, len(aggregate.privilegeSet))
		for privilege := range aggregate.privilegeSet {
			aggregate.Privileges = append(aggregate.Privileges, privilege)
		}
		sort.Strings(aggregate.Privileges)
		permissions = append(permissions, aggregate.r1dbPermission)
	}
	sort.Slice(permissions, func(i, j int) bool {
		left, right := permissions[i], permissions[j]
		for _, values := range [][2]string{
			{left.Database, right.Database},
			{left.Schema, right.Schema},
			{left.Table, right.Table},
			{left.Scope, right.Scope},
			{left.Source, right.Source},
			{left.SourceRole, right.SourceRole},
		} {
			if values[0] == values[1] {
				continue
			}
			return values[0] < values[1]
		}
		return false
	})
	return permissions, nil
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (a *apiV2Server) r1dbReadGrants(
	ctx context.Context, actor username.SQLUsername, query string, target username.SQLUsername,
) ([]string, error) {
	it, err := a.sqlServer.internalExecutor.QueryIteratorEx(
		ctx, "r1db-show-grants", nil,
		sessiondata.InternalExecutorOverride{User: actor}, query,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = it.Close() }()

	var privileges []string
	scanner := makeResultScanner(it.Types())
	ok, err := it.Next(ctx)
	for ; ok; ok, err = it.Next(ctx) {
		row := it.Cur()
		var grantee, value string
		if err := scanner.Scan(row, "grantee", &grantee); err != nil {
			return nil, err
		}
		if !strings.EqualFold(grantee, target.Normalized()) {
			continue
		}
		if err := scanner.Scan(row, "privilege_type", &value); err != nil {
			return nil, err
		}
		for _, privilege := range strings.Split(value, ",") {
			privilege = strings.TrimSpace(privilege)
			if privilege != "" {
				privileges = append(privileges, privilege)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	sort.Strings(privileges)
	return privileges, nil
}

func (a *apiV2Server) r1dbChangeAccess(w http.ResponseWriter, r *http.Request) {
	var req r1dbAccessRequest
	if err := decodeR1DBJSON(w, r, &req); err != nil {
		r1dbRequestError(w, err)
		return
	}
	target, err := r1dbExistingUsername(req.Username)
	if err != nil {
		r1dbRequestError(w, err)
		return
	}
	databases, err := r1dbAccessDatabases(req)
	if err != nil {
		r1dbRequestError(w, err)
		return
	}
	queries := make([]struct {
		database string
		query    string
	}, 0, len(databases)*2)
	for _, database := range databases {
		access := req
		access.Database = database
		query, err := r1dbAccessSQL(access, target)
		if err != nil {
			r1dbRequestError(w, err)
			return
		}
		if strings.EqualFold(strings.TrimSpace(req.Scope), "table") && strings.EqualFold(strings.TrimSpace(req.Action), "grant") {
			userName := target.Normalized()
			queries = append(queries, struct {
				database string
				query    string
			}{database: database, query: fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s", tree.NameStringP(&database), tree.NameStringP(&userName))})
		}
		queries = append(queries, struct {
			database string
			query    string
		}{database: database, query: query})
		if strings.EqualFold(strings.TrimSpace(req.Scope), "database") && strings.EqualFold(strings.TrimSpace(req.Preset), "editor") {
			verb, roleKeyword := "GRANT", "TO"
			if strings.EqualFold(strings.TrimSpace(req.Action), "revoke") {
				verb, roleKeyword = "REVOKE", "FROM"
			}
			userName := target.Normalized()
			queries = append(queries, struct {
				database string
				query    string
			}{database: database, query: fmt.Sprintf("%s CREATE ON SCHEMA %s.public %s %s", verb, tree.NameStringP(&database), roleKeyword, tree.NameStringP(&userName))})
		}
	}

	ctx := a.sqlServer.AnnotateCtx(r.Context())
	actor := userFromHTTPAuthInfoContext(ctx)
	if err := a.sqlServer.internalDB.Txn(ctx, func(ctx context.Context, txn isql.Txn) error {
		for _, access := range queries {
			if _, err := txn.ExecEx(
				ctx, "r1db-change-access", txn.KV(),
				sessiondata.InternalExecutorOverride{User: actor, Database: access.database}, access.query,
			); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		r1dbExecutionError(ctx, w, err)
		return
	}
	writeJSONResponse(ctx, w, http.StatusOK, struct {
		Username  string   `json:"username"`
		Database  string   `json:"database"`
		Databases []string `json:"databases"`
		Table     string   `json:"table,omitempty"`
		Scope     string   `json:"scope"`
		Action    string   `json:"action"`
	}{
		Username: target.Normalized(), Database: databases[0], Databases: databases,
		Table: strings.TrimSpace(req.Table), Scope: strings.ToLower(strings.TrimSpace(req.Scope)),
		Action: strings.ToLower(strings.TrimSpace(req.Action)),
	})
}
