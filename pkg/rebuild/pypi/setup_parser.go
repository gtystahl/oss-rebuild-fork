package pypi

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_python "github.com/tree-sitter/tree-sitter-python/bindings/go"
)

// SetupCall represents a single setup() function call
type SetupCall struct {
	Line           uint                      `json:"line"`
	Column         uint                      `json:"col"`
	PositionalArgs []ExtractedValue          `json:"positional_args"`
	KeywordArgs    map[string]ExtractedValue `json:"keyword_args"`
}

type SetupArguments struct {
	KeywordArgs    map[string]ExtractedValue `json:"keyword_args"`
	PositionalArgs []ExtractedValue          `json:"positional_args"`
}

type CleanedSetupCall struct {
	CallNumber int            `json:"call_number"`
	Location   string         `json:"location"`
	Arguments  SetupArguments `json:"arguments"`
}

// AnalysisResult represents the complete analysis output
type AnalysisResult struct {
	AnalyzedFile string             `json:"analyzed_file"`
	SetupCalls   []CleanedSetupCall `json:"setup_calls"`
}

// SetupAnalyzer analyzes Python code for setup() function calls
type SetupAnalyzer struct {
	sourceCode []byte
	tree       *tree_sitter.Tree
	variables  map[string]ExtractedValue
	imports    map[string]string
	setupCalls []SetupCall
}

type ExtractedValue struct {
	Value interface{} // Has to be any type (interface) cause it can be anything. The exact (Python) type is added as a property here
	Type  string
}

// Analyze performs the full analysis
func (sa *SetupAnalyzer) Analyze() {
	rootNode := sa.tree.RootNode()
	// fmt.Println("Root Node Type:", rootNode.ToSexp())
	sa.traverseNode(rootNode, 0)
}

// traverseNode recursively traverses the AST
func (sa *SetupAnalyzer) traverseNode(node *tree_sitter.Node, level int) {
	if node == nil {
		return
	}

	nodeType := node.GrammarName()
	// fmt.Println("Current Node:", node.Id(), "Type:", nodeType, "Level:", level)

	// GREG TODO - Need to check to make sure these are in the grammar
	switch nodeType {
	case "assignment":
		sa.handleAssignment(node)
	case "augmented_assignment":
		sa.handleAugmentedAssignment(node)
	case "import_statement", "import_from_statement":
		sa.handleImport(node)
	// case "expression_statement":
	// Check if this contains a call expression
	// for i := uint(0); i < node.ChildCount(); i++ {
	// 	child := node.Child(i)
	// 	if child.GrammarName() == "call" {
	// 		sa.handleCall(child)
	// 	}
	// }

	// Only goes through setup calls and only the arguments
	case "call":
		sa.handleCall(node)
	}

	// Recursively visit all children
	for i := uint(0); i < node.ChildCount(); i++ {
		sa.traverseNode(node.Child(i), level+1)
	}
}

// handleAssignment processes variable assignments
func (sa *SetupAnalyzer) handleAssignment(node *tree_sitter.Node) {
	// Find the left side (target) and right side (value)
	var targetNode, valueNode *tree_sitter.Node

	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child.GrammarName() == "identifier" && targetNode == nil {
			targetNode = child
			// Handling typed inputs
		} else if child.GrammarName() != "=" && child.GrammarName() != ":" && valueNode == nil && targetNode != nil {
			valueNode = child
		}
	}

	if targetNode != nil && valueNode != nil {
		varName := sa.getNodeText(targetNode)
		value := sa.extractValue(valueNode, true)
		sa.variables[varName] = value
	}
}

// handleAugmentedAssignment processes augmented assignments (+=, etc.)
func (sa *SetupAnalyzer) handleAugmentedAssignment(node *tree_sitter.Node) {
	// Find target and operator
	var targetNode, valueNode *tree_sitter.Node
	var operator string

	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		childType := child.GrammarName()

		if childType == "identifier" && targetNode == nil {
			targetNode = child
		} else if strings.HasSuffix(childType, "=") {
			operator = childType
		} else if targetNode != nil && valueNode == nil {
			valueNode = child
		}
	}

	if !(targetNode != nil && valueNode != nil && operator != "") {
		return
	}

	varName := sa.getNodeText(targetNode)
	if currentVariable, ok := sa.variables[varName]; !ok {
		newVariableValue := sa.handleSimpleOperations(currentVariable, sa.extractValue(valueNode, true), operator)
		sa.variables[varName] = newVariableValue
	}
}

// handleImport processes import statements
func (sa *SetupAnalyzer) handleImport(node *tree_sitter.Node) {
	nodeType := node.GrammarName()

	if nodeType == "import_statement" {
		// Handle: import module [as alias]
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child.GrammarName() == "dotted_name" {
				moduleName := sa.getNodeText(child)
				sa.imports[moduleName] = moduleName
			} else if child.GrammarName() == "aliased_import" {
				// Get the actual name and alias
				name := ""
				alias := ""
				for j := uint(0); j < child.ChildCount(); j++ {
					subChild := child.Child(j)
					if subChild.GrammarName() == "dotted_name" {
						name = sa.getNodeText(subChild)
					} else if subChild.GrammarName() == "identifier" {
						alias = sa.getNodeText(subChild)
					}
				}
				if alias != "" {
					sa.imports[alias] = name
				} else {
					sa.imports[name] = name
				}
			}
		}
	} else if nodeType == "import_from_statement" {
		// Handle: from module import name [as alias]
		moduleName := ""
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child.GrammarName() == "dotted_name" {
				moduleName = sa.getNodeText(child)
			} else if child.GrammarName() == "identifier" && moduleName == "" {
				moduleName = sa.getNodeText(child)
			}
		}

		// Find imported names
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child.GrammarName() == "dotted_name" && moduleName != "" {
				importedName := sa.getNodeText(child)
				if importedName != moduleName {
					sa.imports[importedName] = moduleName + "." + importedName
				}
			} else if child.GrammarName() == "aliased_import" {
				name := ""
				alias := ""
				for j := uint(0); j < child.ChildCount(); j++ {
					subChild := child.Child(j)
					if subChild.GrammarName() == "identifier" && name == "" {
						name = sa.getNodeText(subChild)
					} else if subChild.GrammarName() == "identifier" {
						alias = sa.getNodeText(subChild)
					}
				}
				if moduleName != "" {
					if alias != "" {
						sa.imports[alias] = moduleName + "." + name
					} else {
						sa.imports[name] = moduleName + "." + name
					}
				}
			}
		}
	}
}

// handleCall processes function calls, looking for setup() calls
func (sa *SetupAnalyzer) handleCall(node *tree_sitter.Node) {
	// Find the function being called
	var functionNode *tree_sitter.Node
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child.GrammarName() == "identifier" || child.GrammarName() == "attribute" {
			functionNode = child
			break
		}
	}

	if functionNode == nil {
		return
	}

	// Check if this is a setup() call
	funcName := sa.getNodeText(functionNode)
	isSetupCall := false

	if functionNode.GrammarName() == "identifier" && funcName == "setup" {
		isSetupCall = true
	} else if functionNode.GrammarName() == "attribute" {
		// Check if the attribute is "setup"
		for i := uint(0); i < functionNode.ChildCount(); i++ {
			child := functionNode.Child(i)
			if child.GrammarName() == "identifier" && sa.getNodeText(child) == "setup" {
				isSetupCall = true
				break
			}
		}
	}

	if !isSetupCall {
		return
	}

	// Extract arguments
	setupCall := SetupCall{
		Line:           node.StartPosition().Row + 1,
		Column:         node.StartPosition().Column,
		PositionalArgs: make([]ExtractedValue, 0),
		KeywordArgs:    make(map[string]ExtractedValue),
	}

	// Find the argument_list node
	var argListNode *tree_sitter.Node
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child.GrammarName() == "argument_list" {
			argListNode = child
			break
		}
	}

	if argListNode != nil {
		for i := uint(0); i < argListNode.ChildCount(); i++ {
			child := argListNode.Child(i)
			childType := child.GrammarName()

			if childType == "keyword_argument" {
				// Extract keyword argument
				var keyNode, valueNode *tree_sitter.Node
				for j := uint(0); j < child.ChildCount(); j++ {
					subChild := child.Child(j)
					if subChild.GrammarName() == "identifier" && keyNode == nil {
						keyNode = subChild
					} else if subChild.GrammarName() != "=" && valueNode == nil && keyNode != nil {
						valueNode = subChild
					}
				}

				if keyNode != nil && valueNode != nil {
					key := sa.getNodeText(keyNode)
					value := sa.extractValue(valueNode, true)
					setupCall.KeywordArgs[key] = value
				}
			} else if childType == "dictionary_splat" {
				// Handle **kwargs
				for j := uint(0); j < child.ChildCount(); j++ {
					subChild := child.Child(j)
					if subChild.GrammarName() != "**" {
						value := sa.extractValue(subChild, true)
						setupCall.KeywordArgs["**kwargs"] = value
					}
				}
			} else if childType != "," && childType != "(" && childType != ")" && childType != "comment" {
				// Positional argument
				value := sa.extractValue(child, true)
				setupCall.PositionalArgs = append(setupCall.PositionalArgs, value)
			}
		}
	}

	sa.setupCalls = append(sa.setupCalls, setupCall)
}

// Not fully implemented yet
func (sa *SetupAnalyzer) handleSimpleOperations(valueOne ExtractedValue, valueTwo ExtractedValue, operator string) ExtractedValue {
	valueOneValue := valueOne.Value
	valueOneType := valueOne.Type

	valueTwoValue := valueTwo.Value
	valueTwoType := valueTwo.Type

	// If things are not perfect, return a default string representation
	if valueOneValue == nil || valueTwoValue == nil || (valueOneType != "" && valueOneType == "defaultString") || (valueTwoType != "" && valueTwoType == "defaultString") {
		return ExtractedValue{
			Value: fmt.Sprintf("<UnhandledExpression: %v %s %v>", valueOneValue, operator, valueTwoValue),
			Type:  "defaultString",
		}
	}

	resultValue := ExtractedValue{
		Value: "UNHANDLED_FUNCTIONALITY",
		Type:  "defaultString",
	}

	// Handle list operations first since they are more complicated
	if operator == "+=" {
		if valueOneType == "list" {
			if valueTwoType == "list" {
				resultValue.Value = append(valueOneValue.([]ExtractedValue), valueTwoValue.([]ExtractedValue)...)
				resultValue.Type = "list"
			} else {
				resultValue.Value = append(valueOneValue.([]ExtractedValue), valueTwo)
				resultValue.Type = "list"
			}
		} else {
			newValue := sa.handleSimpleOperations(valueOne, valueTwo, "+")
			resultValue = newValue
		}
	} else if operator == "*=" {
		if valueOneType == "list" && valueTwoType == "integer" {
			times := int(valueTwoValue.(int64))
			resultValue.Value = make([]ExtractedValue, 0)
			for i := 0; i < times; i++ {
				resultValue.Value = append(resultValue.Value.([]ExtractedValue), valueOneValue.([]ExtractedValue)...)
			}
			resultValue.Type = "list"
		} else {
			newValue := sa.handleSimpleOperations(valueOne, valueTwo, "*")
			resultValue = newValue
		}
	} else if operator == "-=" {
		newValue := sa.handleSimpleOperations(valueOne, valueTwo, "-")
		resultValue = newValue
	} else if operator == "/=" {
		newValue := sa.handleSimpleOperations(valueOne, valueTwo, "/")
		resultValue = newValue
	} else if operator == "+" {
		// Handle addition for strings and numbers
		if valueOneType == "string" && valueTwoType == "string" {
			resultValue.Value = valueOneValue.(string) + valueTwoValue.(string)
			resultValue.Type = "string"
		} else if valueOneType == "integer" && valueTwoType == "integer" {
			resultValue.Value = valueOneValue.(int64) + valueTwoValue.(int64)
			resultValue.Type = "integer"
		} else if (valueOneType == "integer" && valueTwoType == "float") || (valueOneType == "float" && valueTwoType == "integer") {
			var val1, val2 float64
			if valueOneType == "integer" {
				val1 = float64(valueOneValue.(int64))
				val2 = valueTwoValue.(float64)
			} else {
				val1 = valueOneValue.(float64)
				val2 = float64(valueTwoValue.(int64))
			}
			resultValue.Value = val1 + val2
			resultValue.Type = "float"
		} else if valueOneType == "list" && valueTwoType == "list" {
			resultValue.Value = append(valueOneValue.([]ExtractedValue), valueTwoValue.([]ExtractedValue)...)
			resultValue.Type = "list"
		} else {
			resultValue.Value = fmt.Sprintf("<UnhandledExpression: %v %s %v>", valueOneValue, operator, valueTwoValue)
			resultValue.Type = "defaultString"
		}
	} else if operator == "-" {
		// Handle subtraction for numbers
		if valueOneType == "integer" && valueTwoType == "integer" {
			resultValue.Value = valueOneValue.(int64) - valueTwoValue.(int64)
			resultValue.Type = "integer"
		} else if valueOneType == "float" && valueTwoType == "float" {
			resultValue.Value = valueOneValue.(float64) - valueTwoValue.(float64)
			resultValue.Type = "float"
		} else if (valueOneType == "integer" && valueTwoType == "float") || (valueOneType == "float" && valueTwoType == "integer") {
			var val1, val2 float64
			if valueOneType == "integer" {
				val1 = float64(valueOneValue.(int64))
				val2 = valueTwoValue.(float64)
			} else {
				val1 = valueOneValue.(float64)
				val2 = float64(valueTwoValue.(int64))
			}
			resultValue.Value = val1 - val2
			resultValue.Type = "float"
		} else {
			resultValue.Value = fmt.Sprintf("<UnhandledExpression: %v %s %v>", valueOneValue, operator, valueTwoValue)
			resultValue.Type = "defaultString"
		}
	} else if operator == "*" {
		// Handle multiplication for numbers
		if valueOneType == "integer" && valueTwoType == "integer" {
			resultValue.Value = valueOneValue.(int64) * valueTwoValue.(int64)
			resultValue.Type = "integer"
		} else if valueOneType == "float" && valueTwoType == "float" {
			resultValue.Value = valueOneValue.(float64) * valueTwoValue.(float64)
			resultValue.Type = "float"
		} else if (valueOneType == "integer" && valueTwoType == "float") || (valueOneType == "float" && valueTwoType == "integer") {
			var val1, val2 float64
			if valueOneType == "integer" {
				val1 = float64(valueOneValue.(int64))
				val2 = valueTwoValue.(float64)
			} else {
				val1 = valueOneValue.(float64)
				val2 = float64(valueTwoValue.(int64))
			}
			resultValue.Value = val1 * val2
			resultValue.Type = "float"
		} else {
			// For unsupported operations, return a default string representation
			resultValue.Value = fmt.Sprintf("<UnhandledExpression: %v %s %v>", valueOneValue, operator, valueTwoValue)
			resultValue.Type = "defaultString"
		}
	} else if operator == "/" {
		// Handle division for numbers
		if (valueOneType == "integer" || valueOneType == "float") && (valueTwoType == "integer" || valueTwoType == "float") {
			var val1, val2 float64
			if valueOneType == "integer" {
				val1 = float64(valueOneValue.(int64))
			} else {
				val1 = valueOneValue.(float64)
			}
			if valueTwoType == "integer" {
				val2 = float64(valueTwoValue.(int64))
			} else {
				val2 = valueTwoValue.(float64)
			}
			if val2 != 0 {
				resultValue.Value = val1 / val2
				resultValue.Type = "float"
			} else {
				resultValue.Value = "<DivisionByZero>"
				resultValue.Type = "defaultString"
			}
		}
		// Now the conditional operations (only doing it for the same type for now)
	} else if operator == "==" {
		if valueOneType == valueTwoType {
			resultValue.Value = valueOneValue == valueTwoValue
			resultValue.Type = "boolean"
		}
	} else if operator == "!=" {
		if valueOneType == valueTwoType {
			resultValue.Value = valueOneValue != valueTwoValue
			resultValue.Type = "boolean"
		}
	} else if operator == "<" {
		if valueOneType == valueTwoType {
			if valueOneType == "integer" {
				resultValue.Value = valueOneValue.(int64) < valueTwoValue.(int64)
				resultValue.Type = "boolean"
			} else if valueOneType == "float" {
				resultValue.Value = valueOneValue.(float64) < valueTwoValue.(float64)
				resultValue.Type = "boolean"
			} else if valueOneType == "string" {
				resultValue.Value = valueOneValue.(string) < valueTwoValue.(string)
				resultValue.Type = "boolean"
			}
		}
	} else if operator == "<=" {
		if valueOneType == valueTwoType {
			if valueOneType == "integer" {
				resultValue.Value = valueOneValue.(int64) <= valueTwoValue.(int64)
				resultValue.Type = "boolean"
			} else if valueOneType == "float" {
				resultValue.Value = valueOneValue.(float64) <= valueTwoValue.(float64)
				resultValue.Type = "boolean"
			} else if valueOneType == "string" {
				resultValue.Value = valueOneValue.(string) <= valueTwoValue.(string)
				resultValue.Type = "boolean"
			}
		}
	} else if operator == ">" {
		if valueOneType == valueTwoType {
			if valueOneType == "integer" {
				resultValue.Value = valueOneValue.(int64) > valueTwoValue.(int64)
				resultValue.Type = "boolean"
			} else if valueOneType == "float" {
				resultValue.Value = valueOneValue.(float64) > valueTwoValue.(float64)
				resultValue.Type = "boolean"
			} else if valueOneType == "string" {
				resultValue.Value = valueOneValue.(string) > valueTwoValue.(string)
				resultValue.Type = "boolean"
			}
		}
	} else if operator == ">=" {
		if valueOneType == valueTwoType {
			if valueOneType == "integer" {
				resultValue.Value = valueOneValue.(int64) >= valueTwoValue.(int64)
				resultValue.Type = "boolean"
			} else if valueOneType == "float" {
				resultValue.Value = valueOneValue.(float64) >= valueTwoValue.(float64)
				resultValue.Type = "boolean"
			} else if valueOneType == "string" {
				resultValue.Value = valueOneValue.(string) >= valueTwoValue.(string)
				resultValue.Type = "boolean"
			}
		}
	} else {
		// For unsupported operations, return a default string representation
		resultValue.Value = fmt.Sprintf("<UnhandledExpression: %v %s %v>", valueOneValue, operator, valueTwoValue)
		resultValue.Type = "defaultString"
	}

	return resultValue
}

// extractValue converts a tree-sitter node to a Go value
func (sa *SetupAnalyzer) extractValue(node *tree_sitter.Node, resolveVars bool) ExtractedValue {
	var exVal ExtractedValue

	if node == nil {
		return exVal
	}

	nodeType := node.GrammarName()
	// nodeContent := sa.getNodeText(node)
	// fmt.Println(nodeContent)

	switch nodeType {
	case "string":
		// Extract string value, removing quotes
		text := sa.getNodeText(node)
		if len(text) >= 2 {
			// Remove quotes (handle ', ", ''', """)
			if strings.HasPrefix(text, `"""`) || strings.HasPrefix(text, `'''`) {
				if len(text) >= 6 {
					exVal.Value = text[3 : len(text)-3]
					exVal.Type = "string"
					return exVal
				}
			} else if (strings.HasPrefix(text, `"`) && strings.HasSuffix(text, `"`)) ||
				(strings.HasPrefix(text, `'`) && strings.HasSuffix(text, `'`)) {
				exVal.Value = text[1 : len(text)-1]
				exVal.Type = "string"
				return exVal
			}
		}
		exVal.Value = text
		exVal.Type = "string"
		return exVal

	case "integer":
		text := sa.getNodeText(node)
		if val, err := strconv.ParseInt(text, 0, 64); err == nil {
			exVal.Value = val
			exVal.Type = "integer"
			return exVal
		}
		exVal.Value = text
		exVal.Type = "defaultString"
		return exVal

	case "float":
		text := sa.getNodeText(node)
		if val, err := strconv.ParseFloat(text, 64); err == nil {
			exVal.Value = val
			exVal.Type = "float"
			return exVal
		}
		exVal.Value = text
		exVal.Type = "defaultString"
		return exVal

	case "true":
		exVal.Value = true
		exVal.Type = "boolean"
		return exVal

	case "false":
		exVal.Value = false
		exVal.Type = "boolean"
		return exVal

	case "none":
		exVal.Value = nil
		exVal.Type = "null"
		return exVal

	case "list":
		result := make([]ExtractedValue, 0)
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child.GrammarName() != "[" && child.GrammarName() != "]" && child.GrammarName() != "," {
				result = append(result, sa.extractValue(child, resolveVars))
			}
		}
		exVal.Value = result
		exVal.Type = "list"
		return exVal

	case "tuple":
		result := make([]ExtractedValue, 0)
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child.GrammarName() != "(" && child.GrammarName() != ")" && child.GrammarName() != "," {
				result = append(result, sa.extractValue(child, resolveVars))
			}
		}
		exVal.Value = result
		exVal.Type = "tuple"
		return exVal

	case "dictionary":
		result := make(map[string]ExtractedValue)
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child.GrammarName() == "pair" {
				var keyNode, valueNode *tree_sitter.Node
				for j := uint(0); j < child.ChildCount(); j++ {
					subChild := child.Child(j)
					if subChild.GrammarName() != ":" && keyNode == nil {
						keyNode = subChild
					} else if subChild.GrammarName() != ":" && valueNode == nil && keyNode != nil {
						valueNode = subChild
					}
				}
				if keyNode != nil && valueNode != nil {
					keyObj := sa.extractValue(keyNode, resolveVars)
					var key string
					if keyObj.Type != "string" && keyObj.Type != "integer" {
						key = fmt.Sprintf("<unhandled_key_type: %v>", keyObj.Value)
					} else {
						key = fmt.Sprintf("%s", keyObj.Value)
					}
					value := sa.extractValue(valueNode, resolveVars)
					result[key] = value
				}
			}
		}
		exVal.Value = result
		exVal.Type = "dictionary"
		return exVal

	case "subscript":
		// Handle indexing like var[0]
		var valueNode, indexNode *tree_sitter.Node
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child.GrammarName() != "[" && child.GrammarName() != "]" && valueNode == nil {
				valueNode = child
			} else if child.GrammarName() != "[" && child.GrammarName() != "]" && valueNode != nil && indexNode == nil {
				indexNode = child
			}
		}
		if valueNode != nil && indexNode != nil {
			value := sa.extractValue(valueNode, resolveVars)
			index := sa.extractValue(indexNode, resolveVars)

			// Only handling simple cases where value is a list and index is an integer
			if value.Type == "list" && index.Type == "integer" {
				listVal := value.Value.([]ExtractedValue)
				idx := int(index.Value.(int64))
				if idx >= 0 && idx < len(listVal) {
					return listVal[idx]
				}
			} else if value.Type == "dictionary" && index.Type == "string" {
				dictVal := value.Value.(map[string]ExtractedValue)
				if val, ok := dictVal[index.Value.(string)]; ok {
					return val
				}
			} else if value.Type == "dictionary" && index.Type == "integer" {
				// Handle integer keys in dictionaries
				dictVal := value.Value.(map[string]ExtractedValue)
				intKey := fmt.Sprintf("%d", index.Value.(int64))
				if val, ok := dictVal[intKey]; ok {
					return val
				}
			} else if value.Type == "defaultString" {
				exVal.Value = fmt.Sprintf("<subscripted_value: %s[%v]>", value.Value, index.Value)
				exVal.Type = "defaultString"
				return exVal
			}
		}

	case "identifier":
		varName := sa.getNodeText(node)
		if resolveVars {
			if val, ok := sa.variables[varName]; ok {
				return val
			}
		}
		exVal.Value = fmt.Sprintf("<variable: %s>", varName)
		exVal.Type = "defaultString"
		return exVal

	case "attribute":
		// Handle attribute access like obj.attr
		parts := make([]string, 0)
		sa.collectAttributeParts(node, &parts)
		exVal.Value = strings.Join(parts, ".")
		exVal.Type = "defaultString"
		return exVal

	case "call":
		// Handle function calls
		funcName := ""
		args := make([]string, 0)

		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child.GrammarName() == "identifier" || child.GrammarName() == "attribute" {
				funcName = sa.getNodeText(child)
			} else if child.GrammarName() == "argument_list" {
				// Extract first few arguments for preview
				argCount := 0
				for j := uint(0); j < child.ChildCount() && argCount < 2; j++ {
					argChild := child.Child(j)
					if argChild.GrammarName() != "(" && argChild.GrammarName() != ")" && argChild.GrammarName() != "," {
						argVal := sa.extractValue(argChild, resolveVars)
						args = append(args, fmt.Sprintf("%v", argVal))
						argCount++
					}
				}
			}
		}

		argsStr := strings.Join(args, ", ")
		if len(args) >= 2 {
			argsStr += ", ..."
		}
		exVal.Value = fmt.Sprintf("<function_call: %s(%s)>", funcName, argsStr)
		exVal.Type = "defaultString"
		return exVal

	case "binary_operator":
		// Handle operations like a + b
		var left, right *tree_sitter.Node
		var op string

		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			childType := child.GrammarName()

			if left == nil {
				left = child
			} else if isOperator(childType) {
				op = childType
			} else if right == nil {
				right = child
			}
		}

		if left != nil && right != nil && op != "" {
			leftVal := sa.extractValue(left, resolveVars)
			rightVal := sa.extractValue(right, resolveVars)
			return sa.handleSimpleOperations(leftVal, rightVal, op)
		}

	case "comparison_operator":
		// Handle comparisons like a < b
		// Only handling simple two-part comparisons for now
		var operator string
		left := ExtractedValue{
			Value: "",
			Type:  "unsetString",
		}
		right := ExtractedValue{}
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if isOperator(child.GrammarName()) {
				operator = child.GrammarName()
			} else {
				val := sa.extractValue(child, resolveVars)
				if left.Type == "unsetString" {
					left = val
				} else {
					right = val
				}
			}
		}

		return sa.handleSimpleOperations(left, right, operator)

	case "boolean_operator":
		// Handle and/or operations
		// Only handling simple two-part operations for now
		var op string
		left := ExtractedValue{
			Value: "",
			Type:  "unsetString",
		}
		right := ExtractedValue{}
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			childType := child.GrammarName()

			if childType == "and" || childType == "or" {
				op = childType
			} else {
				if left.Type == "unsetString" {
					left = sa.extractValue(child, resolveVars)
				} else {
					right = sa.extractValue(child, resolveVars)
				}
			}
		}

		return sa.handleSimpleOperations(left, right, op)

	case "unary_operator":
		// Handle unary operations like -x, not x
		var op string
		var operand *tree_sitter.Node

		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			childType := child.GrammarName()

			if isOperator(childType) || childType == "not" {
				op = childType
			} else {
				operand = child
			}
		}

		// Not really sure that this works...?
		if operand != nil && op != "" {
			return sa.extractValue(operand, resolveVars)
		}

	case "conditional_expression":
		// Handle ternary: a if condition else b
		var body, test, orelse *tree_sitter.Node

		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			childType := child.GrammarName()

			if childType == "if" || childType == "else" {
				continue
			} else if body == nil {
				body = child
			} else if test == nil {
				test = child
			} else if orelse == nil {
				orelse = child
			}
		}

		if body != nil && test != nil && orelse != nil {
			bodyVal := sa.extractValue(body, resolveVars)
			testVal := sa.extractValue(test, resolveVars)
			elseVal := sa.extractValue(orelse, resolveVars)
			if testVal.Type == "boolean" {
				if testVal.Value.(bool) {
					return bodyVal
				} else {
					return elseVal
				}
			}
		}

	case "parenthesized_expression":
		// Just extract the inner expression
		for i := uint(0); i < node.ChildCount(); i++ {
			child := node.Child(i)
			if child.GrammarName() != "(" && child.GrammarName() != ")" {
				return sa.extractValue(child, resolveVars)
			}
		}
	}

	// Default: return the text representation
	exVal.Value = sa.getNodeText(node)
	exVal.Type = "defaultString"
	return exVal
}

// collectAttributeParts recursively collects parts of an attribute access
func (sa *SetupAnalyzer) collectAttributeParts(node *tree_sitter.Node, parts *[]string) {
	if node == nil {
		return
	}

	if node.GrammarName() == "identifier" {
		*parts = append(*parts, sa.getNodeText(node))
		return
	}

	// For attribute nodes, recursively process
	for i := uint(0); i < node.ChildCount(); i++ {
		child := node.Child(i)
		if child.GrammarName() != "." {
			sa.collectAttributeParts(child, parts)
		}
	}
}

// isOperator checks if a node type represents an operator
func isOperator(nodeType string) bool {
	operators := map[string]bool{
		"+": true, "-": true, "*": true, "/": true, "%": true, "**": true, "//": true,
		"<": true, "<=": true, ">": true, ">=": true, "==": true, "!=": true,
		"<<": true, ">>": true, "&": true, "|": true, "^": true, "~": true,
		"is": true, "in": true, "not": true, "and": true, "or": true,
	}
	return operators[nodeType]
}

// getNodeText extracts the text content of a node
func (sa *SetupAnalyzer) getNodeText(node *tree_sitter.Node) string {
	if node == nil {
		return ""
	}
	startByte := node.StartByte()
	endByte := node.EndByte()
	if endByte > uint(len(sa.sourceCode)) {
		endByte = uint(len(sa.sourceCode))
	}
	return string(sa.sourceCode[startByte:endByte])
}

// GetResult returns the analysis result in the expected format
func (sa *SetupAnalyzer) GetResult(filename string) AnalysisResult {
	setupCallsSummary := make([]CleanedSetupCall, 0)

	for i, call := range sa.setupCalls {
		callSummary := CleanedSetupCall{
			CallNumber: i + 1,
			Location:   fmt.Sprintf("Line %d, Column %d", call.Line, call.Column),
			Arguments: SetupArguments{
				KeywordArgs:    call.KeywordArgs,
				PositionalArgs: call.PositionalArgs,
			},
		}

		setupCallsSummary = append(setupCallsSummary, callSummary)
	}

	return AnalysisResult{
		AnalyzedFile: filename,
		SetupCalls:   setupCallsSummary,
	}
}

func gatherSetupPyData(filename string, sourceCode []byte) AnalysisResult {
	parser := tree_sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(tree_sitter.NewLanguage(tree_sitter_python.Language()))

	tree := parser.Parse(sourceCode, nil)
	defer tree.Close()

	analyzer := &SetupAnalyzer{
		sourceCode: sourceCode,
		tree:       tree,
		variables:  make(map[string]ExtractedValue),
		imports:    make(map[string]string),
		setupCalls: make([]SetupCall, 0),
	}

	analyzer.Analyze()

	// Get results
	result := analyzer.GetResult(filename)
	return result
}

func oldMain() {
	// Read the Python file to analyze
	// filename := "./maliciousSetup.py"
	filename := "./fhirSetup.py"

	sourceCode, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Testing --->
	// parser := tree_sitter.NewParser()
	// defer parser.Close()
	// parser.SetLanguage(tree_sitter.NewLanguage(tree_sitter_python.Language()))

	// tree := parser.Parse(sourceCode, nil)
	// // GREG TODO - This might break things if it closes it too early
	// defer tree.Close()

	// if true {
	// 	fmt.Println("Parsed tree root node type:", tree.RootNode().ToSexp())
	// 	return
	// }
	// <---

	parser := tree_sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(tree_sitter.NewLanguage(tree_sitter_python.Language()))

	tree := parser.Parse(sourceCode, nil)
	defer tree.Close()

	analyzer := &SetupAnalyzer{
		sourceCode: sourceCode,
		tree:       tree,
		variables:  make(map[string]ExtractedValue),
		imports:    make(map[string]string),
		setupCalls: make([]SetupCall, 0),
	}

	analyzer.Analyze()

	// Get and print results
	result := analyzer.GetResult(filename)

	fmt.Println("=" + strings.Repeat("=", 59))
	fmt.Println("SETUP FUNCTION CALL ANALYSIS")
	fmt.Println("=" + strings.Repeat("=", 59))

	if len(analyzer.setupCalls) > 0 {
		fmt.Printf("Found %d setup() call(s):\n", len(analyzer.setupCalls))

		for i, call := range analyzer.setupCalls {
			fmt.Printf("\nSetup Call #%d (Line %d, Column %d):\n", i+1, call.Line, call.Column)
			fmt.Println(strings.Repeat("-", 50))

			if len(call.PositionalArgs) > 0 {
				fmt.Println("Positional Arguments:")
				for j, arg := range call.PositionalArgs {
					fmt.Printf("  [%d]: %v\n", j, arg)
				}
			}

			if len(call.KeywordArgs) > 0 {
				fmt.Println("Keyword Arguments:")
				for key, value := range call.KeywordArgs {
					fmt.Printf("  %s: %v\n", key, value)
				}
			}

			if len(call.PositionalArgs) == 0 && len(call.KeywordArgs) == 0 {
				fmt.Println("  No arguments found")
			}
		}
	} else {
		fmt.Println("No setup() function calls found in the file.")
	}

	// Save to JSON file
	fmt.Println("\n" + "=" + strings.Repeat("=", 59))
	fmt.Println("SAVING SETUP ARGUMENTS TO JSON")
	fmt.Println("=" + strings.Repeat("=", 59))

	outputFilename := "setup_arguments_analysis.json"
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(outputFilename, jsonData, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing JSON file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Setup arguments saved to: %s\n", outputFilename)
	fmt.Println("\nAll analysis completed successfully!")
}
