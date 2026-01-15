package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	sigma "github.com/runreveal/sigmalite"
)

func flattenJSON(prefix string, input map[string]interface{}, output map[string]string) {
	for key, value := range input {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := value.(type) {
		case map[string]interface{}:
			flattenJSON(fullKey, v, output)
		case []interface{}:
			for i, elem := range v {
				arrayKey := fmt.Sprintf("%s[%d]", fullKey, i)
				if elemMap, ok := elem.(map[string]interface{}); ok {
					flattenJSON(arrayKey, elemMap, output)
				} else {
					output[arrayKey] = fmt.Sprintf("%v", elem)
				}
			}
		default:
			output[fullKey] = fmt.Sprintf("%v", value)
		}
	}
}

func Flatten(inputJSON []byte) (map[string]string, error) {
	var input map[string]interface{}
	if err := json.Unmarshal(inputJSON, &input); err != nil {
		return nil, err
	}

	output := make(map[string]string)
	flattenJSON("", input, output)

	return output, nil
}

func runsigma() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 2 {
			return "Invalid no of arguments passed"
		}
		sig := args[0].String()
		j := args[1].String()
		rule, err := sigma.ParseRule([]byte(sig))
		if err != nil {
			return fmt.Sprintf("error: %s", err.Error())
		}

		flattened, err := Flatten([]byte(j))
		if err != nil {
			return fmt.Sprintf("error: %s", err.Error())
		}
		entry := &sigma.LogEntry{
			Message: "Hello foo",
			Fields:  flattened,
		}
		isMatch := rule.Detection.Matches(entry, nil)
		if isMatch {
			return "true"
		}
		return "false"
	})
	return jsonFunc
}

func main() {
	fmt.Println("Go Web Assembly")
	js.Global().Set("runsigma", runsigma())
	<-make(chan struct{})
}
