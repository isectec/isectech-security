package query

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// SecurityQueryLanguage implements a custom query language for security investigations
type SecurityQueryLanguage struct {
	logger  *zap.Logger
	parser  *QueryParser
	builder *QueryBuilder
}

// QueryParser parses security query language expressions
type QueryParser struct {
	logger   *zap.Logger
	keywords map[string]TokenType
	operators map[string]TokenType
}

// QueryBuilder builds backend-specific queries from parsed expressions
type QueryBuilder struct {
	logger          *zap.Logger
	elasticBuilder  *ElasticsearchQueryBuilder
	timescaleBuilder *TimescaleQueryBuilder
}

// Token represents a lexical token
type Token struct {
	Type     TokenType `json:"type"`
	Value    string    `json:"value"`
	Position int       `json:"position"`
	Line     int       `json:"line"`
	Column   int       `json:"column"`
}

// TokenType represents token types
type TokenType int

const (
	// Literals
	IDENTIFIER TokenType = iota
	STRING
	NUMBER
	BOOLEAN
	DATETIME
	IP_ADDRESS
	
	// Keywords
	SELECT
	FROM
	WHERE
	AND
	OR
	NOT
	IN
	LIKE
	BETWEEN
	GROUP_BY
	ORDER_BY
	HAVING
	LIMIT
	
	// Security-specific keywords
	EVENTS
	ALERTS
	THREATS
	ASSETS
	USERS
	NETWORKS
	PROCESSES
	FILES
	
	// Operators
	EQUALS
	NOT_EQUALS
	GREATER_THAN
	LESS_THAN
	GREATER_EQUAL
	LESS_EQUAL
	CONTAINS
	STARTS_WITH
	ENDS_WITH
	REGEX_MATCH
	
	// Functions
	COUNT
	SUM
	AVG
	MIN
	MAX
	DISTINCT
	
	// Time functions
	TIME_BUCKET
	NOW
	AGO
	
	// Security functions
	MITRE_ATTACK
	CVE_LOOKUP
	IOC_MATCH
	THREAT_INTEL
	GEO_LOOKUP
	
	// Punctuation
	LEFT_PAREN
	RIGHT_PAREN
	LEFT_BRACKET
	RIGHT_BRACKET
	COMMA
	SEMICOLON
	DOT
	
	// Special
	EOF
	NEWLINE
	WHITESPACE
	COMMENT
	INVALID
)

// ParsedQuery represents a parsed security query
type ParsedQuery struct {
	Type         QueryType             `json:"type"`
	DataSources  []string              `json:"data_sources"`
	Fields       []string              `json:"fields"`
	Conditions   []Condition           `json:"conditions"`
	Aggregations []Aggregation         `json:"aggregations"`
	Grouping     []string              `json:"grouping"`
	Sorting      []SortExpression      `json:"sorting"`
	TimeRange    *TimeRangeExpression  `json:"time_range"`
	Limit        int                   `json:"limit"`
	Functions    []FunctionCall        `json:"functions"`
	Metadata     *QueryMetadata        `json:"metadata"`
}

// QueryType represents different types of queries
type QueryType int

const (
	SEARCH_QUERY QueryType = iota
	AGGREGATION_QUERY
	TIMESERIES_QUERY
	THREAT_HUNT_QUERY
	INVESTIGATION_QUERY
)

// Condition represents a query condition
type Condition struct {
	Field     string      `json:"field"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
	LogicalOp string      `json:"logical_op,omitempty"` // AND, OR, NOT
	Group     int         `json:"group,omitempty"`
}

// Aggregation represents an aggregation expression
type Aggregation struct {
	Function string `json:"function"`
	Field    string `json:"field"`
	Alias    string `json:"alias,omitempty"`
}

// SortExpression represents a sort expression
type SortExpression struct {
	Field     string `json:"field"`
	Direction string `json:"direction"` // ASC, DESC
}

// TimeRangeExpression represents a time range expression
type TimeRangeExpression struct {
	From     interface{} `json:"from"` // timestamp or relative expression
	To       interface{} `json:"to"`   // timestamp or relative expression
	Interval string      `json:"interval,omitempty"`
}

// FunctionCall represents a function call
type FunctionCall struct {
	Name      string        `json:"name"`
	Arguments []interface{} `json:"arguments"`
	Alias     string        `json:"alias,omitempty"`
}

// ElasticsearchQueryBuilder builds Elasticsearch queries
type ElasticsearchQueryBuilder struct {
	logger *zap.Logger
}

// TimescaleQueryBuilder builds TimescaleDB queries
type TimescaleQueryBuilder struct {
	logger *zap.Logger
}

// NewSecurityQueryLanguage creates a new security query language processor
func NewSecurityQueryLanguage(logger *zap.Logger) *SecurityQueryLanguage {
	parser := &QueryParser{
		logger:   logger.With(zap.String("component", "query-parser")),
		keywords: initializeKeywords(),
		operators: initializeOperators(),
	}
	
	builder := &QueryBuilder{
		logger:           logger.With(zap.String("component", "query-builder")),
		elasticBuilder:   &ElasticsearchQueryBuilder{logger: logger},
		timescaleBuilder: &TimescaleQueryBuilder{logger: logger},
	}
	
	return &SecurityQueryLanguage{
		logger:  logger.With(zap.String("component", "security-query-language")),
		parser:  parser,
		builder: builder,
	}
}

// initializeKeywords initializes language keywords
func initializeKeywords() map[string]TokenType {
	return map[string]TokenType{
		"select":     SELECT,
		"from":       FROM,
		"where":      WHERE,
		"and":        AND,
		"or":         OR,
		"not":        NOT,
		"in":         IN,
		"like":       LIKE,
		"between":    BETWEEN,
		"group":      GROUP_BY,
		"by":         GROUP_BY,
		"order":      ORDER_BY,
		"having":     HAVING,
		"limit":      LIMIT,
		"events":     EVENTS,
		"alerts":     ALERTS,
		"threats":    THREATS,
		"assets":     ASSETS,
		"users":      USERS,
		"networks":   NETWORKS,
		"processes":  PROCESSES,
		"files":      FILES,
		"count":      COUNT,
		"sum":        SUM,
		"avg":        AVG,
		"min":        MIN,
		"max":        MAX,
		"distinct":   DISTINCT,
		"now":        NOW,
		"ago":        AGO,
		"mitre":      MITRE_ATTACK,
		"cve":        CVE_LOOKUP,
		"ioc":        IOC_MATCH,
		"threat":     THREAT_INTEL,
		"geo":        GEO_LOOKUP,
		"true":       BOOLEAN,
		"false":      BOOLEAN,
	}
}

// initializeOperators initializes operators
func initializeOperators() map[string]TokenType {
	return map[string]TokenType{
		"=":         EQUALS,
		"!=":        NOT_EQUALS,
		"<>":        NOT_EQUALS,
		">":         GREATER_THAN,
		"<":         LESS_THAN,
		">=":        GREATER_EQUAL,
		"<=":        LESS_EQUAL,
		"contains":  CONTAINS,
		"startswith": STARTS_WITH,
		"endswith":  ENDS_WITH,
		"matches":   REGEX_MATCH,
	}
}

// Parse parses a security query language expression
func (sql *SecurityQueryLanguage) Parse(queryText string) (*ParsedQuery, error) {
	// Tokenize the input
	tokens, err := sql.parser.tokenize(queryText)
	if err != nil {
		return nil, fmt.Errorf("tokenization failed: %w", err)
	}
	
	// Parse tokens into AST
	query, err := sql.parser.parseTokens(tokens)
	if err != nil {
		return nil, fmt.Errorf("parsing failed: %w", err)
	}
	
	// Validate and optimize query
	if err := sql.validateQuery(query); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}
	
	sql.logger.Debug("Query parsed successfully",
		zap.String("type", fmt.Sprintf("%d", query.Type)),
		zap.Strings("data_sources", query.DataSources),
		zap.Int("conditions", len(query.Conditions)),
	)
	
	return query, nil
}

// BuildElasticsearchQuery builds an Elasticsearch query from parsed query
func (sql *SecurityQueryLanguage) BuildElasticsearchQuery(parsedQuery *ParsedQuery) (map[string]interface{}, error) {
	return sql.builder.elasticBuilder.Build(parsedQuery)
}

// BuildTimescaleQuery builds a TimescaleDB query from parsed query
func (sql *SecurityQueryLanguage) BuildTimescaleQuery(parsedQuery *ParsedQuery) (string, []interface{}, error) {
	return sql.builder.timescaleBuilder.Build(parsedQuery)
}

// tokenize breaks input text into tokens
func (qp *QueryParser) tokenize(input string) ([]Token, error) {
	var tokens []Token
	pos := 0
	line := 1
	column := 1
	
	for pos < len(input) {
		// Skip whitespace
		if isWhitespace(input[pos]) {
			if input[pos] == '\n' {
				line++
				column = 1
			} else {
				column++
			}
			pos++
			continue
		}
		
		// Skip comments
		if pos < len(input)-1 && input[pos:pos+2] == "--" {
			for pos < len(input) && input[pos] != '\n' {
				pos++
			}
			continue
		}
		
		// String literals
		if input[pos] == '"' || input[pos] == '\'' {
			token, newPos, err := qp.parseString(input, pos, line, column)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, token)
			column += newPos - pos
			pos = newPos
			continue
		}
		
		// Numbers
		if isDigit(input[pos]) {
			token, newPos := qp.parseNumber(input, pos, line, column)
			tokens = append(tokens, token)
			column += newPos - pos
			pos = newPos
			continue
		}
		
		// IP addresses
		if isIPStart(input, pos) {
			token, newPos := qp.parseIPAddress(input, pos, line, column)
			tokens = append(tokens, token)
			column += newPos - pos
			pos = newPos
			continue
		}
		
		// DateTime
		if isDateTimeStart(input, pos) {
			token, newPos := qp.parseDateTime(input, pos, line, column)
			tokens = append(tokens, token)
			column += newPos - pos
			pos = newPos
			continue
		}
		
		// Operators (multi-character first)
		if opToken, newPos := qp.parseOperator(input, pos, line, column); opToken.Type != INVALID {
			tokens = append(tokens, opToken)
			column += newPos - pos
			pos = newPos
			continue
		}
		
		// Identifiers and keywords
		if isAlpha(input[pos]) || input[pos] == '_' {
			token, newPos := qp.parseIdentifier(input, pos, line, column)
			tokens = append(tokens, token)
			column += newPos - pos
			pos = newPos
			continue
		}
		
		// Single character tokens
		switch input[pos] {
		case '(':
			tokens = append(tokens, Token{LEFT_PAREN, "(", pos, line, column})
		case ')':
			tokens = append(tokens, Token{RIGHT_PAREN, ")", pos, line, column})
		case '[':
			tokens = append(tokens, Token{LEFT_BRACKET, "[", pos, line, column})
		case ']':
			tokens = append(tokens, Token{RIGHT_BRACKET, "]", pos, line, column})
		case ',':
			tokens = append(tokens, Token{COMMA, ",", pos, line, column})
		case ';':
			tokens = append(tokens, Token{SEMICOLON, ";", pos, line, column})
		case '.':
			tokens = append(tokens, Token{DOT, ".", pos, line, column})
		default:
			return nil, fmt.Errorf("unexpected character '%c' at line %d, column %d", input[pos], line, column)
		}
		
		pos++
		column++
	}
	
	tokens = append(tokens, Token{EOF, "", pos, line, column})
	return tokens, nil
}

// parseTokens parses tokens into a ParsedQuery
func (qp *QueryParser) parseTokens(tokens []Token) (*ParsedQuery, error) {
	parser := &tokenParser{
		tokens:   tokens,
		current:  0,
		logger:   qp.logger,
	}
	
	return parser.parseQuery()
}

// tokenParser handles token parsing
type tokenParser struct {
	tokens  []Token
	current int
	logger  *zap.Logger
}

// parseQuery parses the main query structure
func (tp *tokenParser) parseQuery() (*ParsedQuery, error) {
	query := &ParsedQuery{
		Type:         SEARCH_QUERY,
		DataSources:  []string{},
		Fields:       []string{},
		Conditions:   []Condition{},
		Aggregations: []Aggregation{},
		Grouping:     []string{},
		Sorting:      []SortExpression{},
		Functions:    []FunctionCall{},
		Metadata:     &QueryMetadata{},
	}
	
	// Parse SELECT clause
	if tp.match(SELECT) {
		fields, aggs, funcs, err := tp.parseSelectClause()
		if err != nil {
			return nil, err
		}
		query.Fields = fields
		query.Aggregations = aggs
		query.Functions = funcs
		
		if len(aggs) > 0 || len(funcs) > 0 {
			query.Type = AGGREGATION_QUERY
		}
	}
	
	// Parse FROM clause
	if tp.match(FROM) {
		dataSources, err := tp.parseFromClause()
		if err != nil {
			return nil, err
		}
		query.DataSources = dataSources
	}
	
	// Parse WHERE clause
	if tp.match(WHERE) {
		conditions, timeRange, err := tp.parseWhereClause()
		if err != nil {
			return nil, err
		}
		query.Conditions = conditions
		query.TimeRange = timeRange
	}
	
	// Parse GROUP BY clause
	if tp.matchSequence(GROUP_BY) {
		grouping, err := tp.parseGroupByClause()
		if err != nil {
			return nil, err
		}
		query.Grouping = grouping
		query.Type = AGGREGATION_QUERY
	}
	
	// Parse ORDER BY clause
	if tp.matchSequence(ORDER_BY) {
		sorting, err := tp.parseOrderByClause()
		if err != nil {
			return nil, err
		}
		query.Sorting = sorting
	}
	
	// Parse LIMIT clause
	if tp.match(LIMIT) {
		limit, err := tp.parseLimitClause()
		if err != nil {
			return nil, err
		}
		query.Limit = limit
	}
	
	return query, nil
}

// parseSelectClause parses the SELECT clause
func (tp *tokenParser) parseSelectClause() ([]string, []Aggregation, []FunctionCall, error) {
	var fields []string
	var aggregations []Aggregation
	var functions []FunctionCall
	
	for {
		if tp.check(FROM) || tp.isAtEnd() {
			break
		}
		
		// Check for aggregation functions
		if tp.isAggregationFunction() {
			agg, err := tp.parseAggregation()
			if err != nil {
				return nil, nil, nil, err
			}
			aggregations = append(aggregations, agg)
		} else if tp.isSecurityFunction() {
			fn, err := tp.parseFunction()
			if err != nil {
				return nil, nil, nil, err
			}
			functions = append(functions, fn)
		} else {
			// Regular field
			if tp.check(IDENTIFIER) {
				fields = append(fields, tp.advance().Value)
			} else {
				return nil, nil, nil, fmt.Errorf("expected field name")
			}
		}
		
		if !tp.match(COMMA) {
			break
		}
	}
	
	return fields, aggregations, functions, nil
}

// parseFromClause parses the FROM clause
func (tp *tokenParser) parseFromClause() ([]string, error) {
	var dataSources []string
	
	for {
		if tp.check(WHERE) || tp.check(GROUP_BY) || tp.check(ORDER_BY) || tp.check(LIMIT) || tp.isAtEnd() {
			break
		}
		
		if tp.check(IDENTIFIER) || tp.isDataSourceKeyword() {
			dataSources = append(dataSources, tp.advance().Value)
		} else {
			return nil, fmt.Errorf("expected data source name")
		}
		
		if !tp.match(COMMA) {
			break
		}
	}
	
	return dataSources, nil
}

// parseWhereClause parses the WHERE clause
func (tp *tokenParser) parseWhereClause() ([]Condition, *TimeRangeExpression, error) {
	var conditions []Condition
	var timeRange *TimeRangeExpression
	
	for {
		if tp.check(GROUP_BY) || tp.check(ORDER_BY) || tp.check(LIMIT) || tp.isAtEnd() {
			break
		}
		
		condition, err := tp.parseCondition()
		if err != nil {
			return nil, nil, err
		}
		
		// Check if this is a time range condition
		if condition.Field == "@timestamp" || condition.Field == "timestamp" {
			if timeRange == nil {
				timeRange = &TimeRangeExpression{}
			}
			tp.updateTimeRange(timeRange, condition)
		} else {
			conditions = append(conditions, condition)
		}
		
		// Check for logical operators
		if tp.match(AND) {
			// Continue parsing
		} else if tp.match(OR) {
			// Set logical operator for next condition
		} else {
			break
		}
	}
	
	return conditions, timeRange, nil
}

// parseCondition parses a single condition
func (tp *tokenParser) parseCondition() (Condition, error) {
	condition := Condition{}
	
	// Parse field name
	if tp.check(IDENTIFIER) {
		condition.Field = tp.advance().Value
	} else {
		return condition, fmt.Errorf("expected field name")
	}
	
	// Parse operator
	if tp.isOperator() {
		condition.Operator = tp.advance().Value
	} else {
		return condition, fmt.Errorf("expected operator")
	}
	
	// Parse value
	if tp.check(STRING) || tp.check(NUMBER) || tp.check(BOOLEAN) || 
	   tp.check(DATETIME) || tp.check(IP_ADDRESS) {
		condition.Value = tp.parseValue()
	} else if tp.match(LEFT_PAREN) {
		// Parse list of values for IN operator
		var values []interface{}
		for {
			if tp.check(RIGHT_PAREN) {
				break
			}
			values = append(values, tp.parseValue())
			if !tp.match(COMMA) {
				break
			}
		}
		tp.consume(RIGHT_PAREN, "expected ')' after value list")
		condition.Value = values
	} else {
		return condition, fmt.Errorf("expected value")
	}
	
	return condition, nil
}

// Build builds an Elasticsearch query from parsed query
func (eqb *ElasticsearchQueryBuilder) Build(parsedQuery *ParsedQuery) (map[string]interface{}, error) {
	query := map[string]interface{}{
		"bool": map[string]interface{}{
			"must":   []interface{}{},
			"filter": []interface{}{},
		},
	}
	
	boolQuery := query["bool"].(map[string]interface{})
	mustQueries := boolQuery["must"].([]interface{})
	filterQueries := boolQuery["filter"].([]interface{})
	
	// Add conditions
	for _, condition := range parsedQuery.Conditions {
		esCondition := eqb.buildCondition(condition)
		if condition.LogicalOp == "NOT" {
			if boolQuery["must_not"] == nil {
				boolQuery["must_not"] = []interface{}{}
			}
			mustNotQueries := boolQuery["must_not"].([]interface{})
			mustNotQueries = append(mustNotQueries, esCondition)
			boolQuery["must_not"] = mustNotQueries
		} else {
			mustQueries = append(mustQueries, esCondition)
		}
	}
	
	// Add time range filter
	if parsedQuery.TimeRange != nil {
		timeFilter := eqb.buildTimeRange(parsedQuery.TimeRange)
		filterQueries = append(filterQueries, timeFilter)
	}
	
	boolQuery["must"] = mustQueries
	boolQuery["filter"] = filterQueries
	
	// Build aggregations
	if len(parsedQuery.Aggregations) > 0 {
		aggs := make(map[string]interface{})
		for _, agg := range parsedQuery.Aggregations {
			aggName := agg.Alias
			if aggName == "" {
				aggName = fmt.Sprintf("%s_%s", agg.Function, agg.Field)
			}
			aggs[aggName] = map[string]interface{}{
				agg.Function: map[string]interface{}{
					"field": agg.Field,
				},
			}
		}
		return map[string]interface{}{
			"query": query,
			"aggs":  aggs,
			"size":  0,
		}, nil
	}
	
	result := map[string]interface{}{
		"query": query,
	}
	
	// Add sort
	if len(parsedQuery.Sorting) > 0 {
		sort := make([]map[string]interface{}, len(parsedQuery.Sorting))
		for i, s := range parsedQuery.Sorting {
			sort[i] = map[string]interface{}{
				s.Field: map[string]interface{}{
					"order": strings.ToLower(s.Direction),
				},
			}
		}
		result["sort"] = sort
	}
	
	// Add size limit
	if parsedQuery.Limit > 0 {
		result["size"] = parsedQuery.Limit
	}
	
	return result, nil
}

// buildCondition builds an Elasticsearch condition
func (eqb *ElasticsearchQueryBuilder) buildCondition(condition Condition) map[string]interface{} {
	switch condition.Operator {
	case "=":
		return map[string]interface{}{
			"term": map[string]interface{}{
				condition.Field: condition.Value,
			},
		}
	case "!=":
		return map[string]interface{}{
			"bool": map[string]interface{}{
				"must_not": map[string]interface{}{
					"term": map[string]interface{}{
						condition.Field: condition.Value,
					},
				},
			},
		}
	case "contains":
		return map[string]interface{}{
			"wildcard": map[string]interface{}{
				condition.Field: fmt.Sprintf("*%v*", condition.Value),
			},
		}
	case "matches":
		return map[string]interface{}{
			"regexp": map[string]interface{}{
				condition.Field: condition.Value,
			},
		}
	case "in":
		return map[string]interface{}{
			"terms": map[string]interface{}{
				condition.Field: condition.Value,
			},
		}
	case ">":
		return map[string]interface{}{
			"range": map[string]interface{}{
				condition.Field: map[string]interface{}{
					"gt": condition.Value,
				},
			},
		}
	case ">=":
		return map[string]interface{}{
			"range": map[string]interface{}{
				condition.Field: map[string]interface{}{
					"gte": condition.Value,
				},
			},
		}
	case "<":
		return map[string]interface{}{
			"range": map[string]interface{}{
				condition.Field: map[string]interface{}{
					"lt": condition.Value,
				},
			},
		}
	case "<=":
		return map[string]interface{}{
			"range": map[string]interface{}{
				condition.Field: map[string]interface{}{
					"lte": condition.Value,
				},
			},
		}
	default:
		// Default to term query
		return map[string]interface{}{
			"term": map[string]interface{}{
				condition.Field: condition.Value,
			},
		}
	}
}

// buildTimeRange builds an Elasticsearch time range filter
func (eqb *ElasticsearchQueryBuilder) buildTimeRange(timeRange *TimeRangeExpression) map[string]interface{} {
	rangeQuery := map[string]interface{}{
		"range": map[string]interface{}{
			"@timestamp": map[string]interface{}{},
		},
	}
	
	timestampRange := rangeQuery["range"].(map[string]interface{})["@timestamp"].(map[string]interface{})
	
	if timeRange.From != nil {
		timestampRange["gte"] = timeRange.From
	}
	
	if timeRange.To != nil {
		timestampRange["lte"] = timeRange.To
	}
	
	return rangeQuery
}

// Build builds a TimescaleDB query from parsed query
func (tqb *TimescaleQueryBuilder) Build(parsedQuery *ParsedQuery) (string, []interface{}, error) {
	var parts []string
	var args []interface{}
	argCount := 0
	
	// SELECT clause
	if len(parsedQuery.Fields) > 0 {
		parts = append(parts, "SELECT "+strings.Join(parsedQuery.Fields, ", "))
	} else if len(parsedQuery.Aggregations) > 0 {
		var aggFields []string
		for _, agg := range parsedQuery.Aggregations {
			aggField := fmt.Sprintf("%s(%s)", strings.ToUpper(agg.Function), agg.Field)
			if agg.Alias != "" {
				aggField += " AS " + agg.Alias
			}
			aggFields = append(aggFields, aggField)
		}
		parts = append(parts, "SELECT "+strings.Join(aggFields, ", "))
	} else {
		parts = append(parts, "SELECT *")
	}
	
	// FROM clause
	if len(parsedQuery.DataSources) > 0 {
		parts = append(parts, "FROM "+strings.Join(parsedQuery.DataSources, ", "))
	}
	
	// WHERE clause
	if len(parsedQuery.Conditions) > 0 || parsedQuery.TimeRange != nil {
		var whereConditions []string
		
		// Add time range condition
		if parsedQuery.TimeRange != nil {
			if parsedQuery.TimeRange.From != nil {
				argCount++
				whereConditions = append(whereConditions, fmt.Sprintf("timestamp >= $%d", argCount))
				args = append(args, parsedQuery.TimeRange.From)
			}
			if parsedQuery.TimeRange.To != nil {
				argCount++
				whereConditions = append(whereConditions, fmt.Sprintf("timestamp <= $%d", argCount))
				args = append(args, parsedQuery.TimeRange.To)
			}
		}
		
		// Add other conditions
		for _, condition := range parsedQuery.Conditions {
			conditionSQL, conditionArgs := tqb.buildCondition(condition, argCount)
			whereConditions = append(whereConditions, conditionSQL)
			args = append(args, conditionArgs...)
			argCount += len(conditionArgs)
		}
		
		if len(whereConditions) > 0 {
			parts = append(parts, "WHERE "+strings.Join(whereConditions, " AND "))
		}
	}
	
	// GROUP BY clause
	if len(parsedQuery.Grouping) > 0 {
		parts = append(parts, "GROUP BY "+strings.Join(parsedQuery.Grouping, ", "))
	}
	
	// ORDER BY clause
	if len(parsedQuery.Sorting) > 0 {
		var orderFields []string
		for _, sort := range parsedQuery.Sorting {
			orderFields = append(orderFields, fmt.Sprintf("%s %s", sort.Field, sort.Direction))
		}
		parts = append(parts, "ORDER BY "+strings.Join(orderFields, ", "))
	}
	
	// LIMIT clause
	if parsedQuery.Limit > 0 {
		argCount++
		parts = append(parts, fmt.Sprintf("LIMIT $%d", argCount))
		args = append(args, parsedQuery.Limit)
	}
	
	query := strings.Join(parts, " ")
	return query, args, nil
}

// buildCondition builds a TimescaleDB condition
func (tqb *TimescaleQueryBuilder) buildCondition(condition Condition, argOffset int) (string, []interface{}) {
	switch condition.Operator {
	case "=":
		return fmt.Sprintf("%s = $%d", condition.Field, argOffset+1), []interface{}{condition.Value}
	case "!=":
		return fmt.Sprintf("%s != $%d", condition.Field, argOffset+1), []interface{}{condition.Value}
	case ">":
		return fmt.Sprintf("%s > $%d", condition.Field, argOffset+1), []interface{}{condition.Value}
	case ">=":
		return fmt.Sprintf("%s >= $%d", condition.Field, argOffset+1), []interface{}{condition.Value}
	case "<":
		return fmt.Sprintf("%s < $%d", condition.Field, argOffset+1), []interface{}{condition.Value}
	case "<=":
		return fmt.Sprintf("%s <= $%d", condition.Field, argOffset+1), []interface{}{condition.Value}
	case "contains":
		return fmt.Sprintf("%s ILIKE $%d", condition.Field, argOffset+1), []interface{}{"%" + fmt.Sprintf("%v", condition.Value) + "%"}
	case "startswith":
		return fmt.Sprintf("%s ILIKE $%d", condition.Field, argOffset+1), []interface{}{fmt.Sprintf("%v", condition.Value) + "%"}
	case "endswith":
		return fmt.Sprintf("%s ILIKE $%d", condition.Field, argOffset+1), []interface{}{"%" + fmt.Sprintf("%v", condition.Value)}
	case "matches":
		return fmt.Sprintf("%s ~ $%d", condition.Field, argOffset+1), []interface{}{condition.Value}
	case "in":
		if values, ok := condition.Value.([]interface{}); ok {
			placeholders := make([]string, len(values))
			for i := range values {
				placeholders[i] = fmt.Sprintf("$%d", argOffset+1+i)
			}
			return fmt.Sprintf("%s IN (%s)", condition.Field, strings.Join(placeholders, ", ")), values
		}
		return fmt.Sprintf("%s = $%d", condition.Field, argOffset+1), []interface{}{condition.Value}
	default:
		return fmt.Sprintf("%s = $%d", condition.Field, argOffset+1), []interface{}{condition.Value}
	}
}

// Helper functions

func (tp *tokenParser) match(tokenType TokenType) bool {
	if tp.check(tokenType) {
		tp.advance()
		return true
	}
	return false
}

func (tp *tokenParser) matchSequence(tokenTypes ...TokenType) bool {
	saved := tp.current
	for _, tokenType := range tokenTypes {
		if !tp.match(tokenType) {
			tp.current = saved
			return false
		}
	}
	return true
}

func (tp *tokenParser) check(tokenType TokenType) bool {
	if tp.isAtEnd() {
		return false
	}
	return tp.peek().Type == tokenType
}

func (tp *tokenParser) advance() Token {
	if !tp.isAtEnd() {
		tp.current++
	}
	return tp.previous()
}

func (tp *tokenParser) isAtEnd() bool {
	return tp.peek().Type == EOF
}

func (tp *tokenParser) peek() Token {
	return tp.tokens[tp.current]
}

func (tp *tokenParser) previous() Token {
	return tp.tokens[tp.current-1]
}

func (tp *tokenParser) consume(tokenType TokenType, message string) (Token, error) {
	if tp.check(tokenType) {
		return tp.advance(), nil
	}
	return Token{}, fmt.Errorf("%s at line %d", message, tp.peek().Line)
}

func (tp *tokenParser) isAggregationFunction() bool {
	return tp.check(COUNT) || tp.check(SUM) || tp.check(AVG) || tp.check(MIN) || tp.check(MAX) || tp.check(DISTINCT)
}

func (tp *tokenParser) isSecurityFunction() bool {
	return tp.check(MITRE_ATTACK) || tp.check(CVE_LOOKUP) || tp.check(IOC_MATCH) || tp.check(THREAT_INTEL) || tp.check(GEO_LOOKUP)
}

func (tp *tokenParser) isDataSourceKeyword() bool {
	return tp.check(EVENTS) || tp.check(ALERTS) || tp.check(THREATS) || tp.check(ASSETS) || 
		   tp.check(USERS) || tp.check(NETWORKS) || tp.check(PROCESSES) || tp.check(FILES)
}

func (tp *tokenParser) isOperator() bool {
	return tp.check(EQUALS) || tp.check(NOT_EQUALS) || tp.check(GREATER_THAN) || 
		   tp.check(LESS_THAN) || tp.check(GREATER_EQUAL) || tp.check(LESS_EQUAL) ||
		   tp.check(CONTAINS) || tp.check(STARTS_WITH) || tp.check(ENDS_WITH) || tp.check(REGEX_MATCH) ||
		   tp.check(IN) || tp.check(LIKE) || tp.check(BETWEEN)
}

func (tp *tokenParser) parseValue() interface{} {
	token := tp.advance()
	switch token.Type {
	case STRING:
		return strings.Trim(token.Value, "\"'")
	case NUMBER:
		if strings.Contains(token.Value, ".") {
			if f, err := strconv.ParseFloat(token.Value, 64); err == nil {
				return f
			}
		} else {
			if i, err := strconv.ParseInt(token.Value, 10, 64); err == nil {
				return i
			}
		}
		return token.Value
	case BOOLEAN:
		return token.Value == "true"
	case DATETIME:
		if t, err := time.Parse(time.RFC3339, token.Value); err == nil {
			return t
		}
		return token.Value
	case IP_ADDRESS:
		return token.Value
	default:
		return token.Value
	}
}

func (tp *tokenParser) parseAggregation() (Aggregation, error) {
	// Implementation for parsing aggregation functions
	return Aggregation{}, nil
}

func (tp *tokenParser) parseFunction() (FunctionCall, error) {
	// Implementation for parsing security functions
	return FunctionCall{}, nil
}

func (tp *tokenParser) parseGroupByClause() ([]string, error) {
	// Implementation for parsing GROUP BY clause
	return []string{}, nil
}

func (tp *tokenParser) parseOrderByClause() ([]SortExpression, error) {
	// Implementation for parsing ORDER BY clause
	return []SortExpression{}, nil
}

func (tp *tokenParser) parseLimitClause() (int, error) {
	// Implementation for parsing LIMIT clause
	return 0, nil
}

func (tp *tokenParser) updateTimeRange(timeRange *TimeRangeExpression, condition Condition) {
	// Implementation for updating time range from conditions
}

// Utility functions for tokenization
func isWhitespace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIPStart(input string, pos int) bool {
	// Simple check for IP address pattern
	ipRegex := regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
	return ipRegex.MatchString(input[pos:])
}

func isDateTimeStart(input string, pos int) bool {
	// Simple check for datetime pattern
	dateRegex := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}`)
	return dateRegex.MatchString(input[pos:])
}

func (qp *QueryParser) parseString(input string, pos, line, column int) (Token, int, error) {
	// Implementation for parsing string literals
	return Token{STRING, "", pos, line, column}, pos, nil
}

func (qp *QueryParser) parseNumber(input string, pos, line, column int) (Token, int) {
	// Implementation for parsing numbers
	return Token{NUMBER, "", pos, line, column}, pos
}

func (qp *QueryParser) parseIPAddress(input string, pos, line, column int) (Token, int) {
	// Implementation for parsing IP addresses
	return Token{IP_ADDRESS, "", pos, line, column}, pos
}

func (qp *QueryParser) parseDateTime(input string, pos, line, column int) (Token, int) {
	// Implementation for parsing datetime
	return Token{DATETIME, "", pos, line, column}, pos
}

func (qp *QueryParser) parseOperator(input string, pos, line, column int) (Token, int) {
	// Implementation for parsing operators
	return Token{INVALID, "", pos, line, column}, pos
}

func (qp *QueryParser) parseIdentifier(input string, pos, line, column int) (Token, int) {
	// Implementation for parsing identifiers
	return Token{IDENTIFIER, "", pos, line, column}, pos
}

// validateQuery validates the parsed query
func (sql *SecurityQueryLanguage) validateQuery(query *ParsedQuery) error {
	// Basic validation
	if len(query.DataSources) == 0 {
		query.DataSources = []string{"events"} // Default data source
	}
	
	// Validate field references
	// Implementation would check field existence and types
	
	return nil
}