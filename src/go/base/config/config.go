// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"gopkg.in/yaml.v2"

	"clusterfuzz/go/base/environ"
	"clusterfuzz/go/base/fs"
	"clusterfuzz/go/base/logs"
)

const (
	projectPath = "project"
	separator   = "."
	yamlExt     = ".yaml"
)

// Config represents a config object.
type Config struct {
	root      string
	configDir string
}

// Node represents a Config Node which might be either a value or a group of
// values such as a slice or a map.
type Node struct {
	body interface{}
}

// Body returns the Config Node value as an interface{}.
func (n *Node) Body() interface{} {
	return n.body
}

// Int returns the Config Node value asserted to an int.
func (n *Node) Int() int {
	result, ok := (n.body).(int)
	if !ok {
		logs.Panicf("failed to convert yaml node to an int: %+v", n.body)
	}
	return result
}

// Map returns the Config Node value asserted to a map[string]interface{}.
func (n *Node) Map() map[string]interface{} {
	// Go doesn't allow to assert directly to map[string]interface{}.
	body, ok := (n.body).(map[interface{}]interface{})
	if !ok {
		logs.Panicf("failed to convert yaml node to a map: %+v", n.body)
	}

	result := make(map[string]interface{})
	for key, value := range body {
		if keyStr, ok := key.(string); ok {
			result[keyStr] = value
		} else {
			logs.Panicf("filed to convert a key in yaml file to a string: %+v", key)
		}
	}

	return result
}

// Slice returns the Config Node value asserted to a slice []interface{}.
func (n *Node) Slice() []interface{} {
	result, ok := (n.body).([]interface{})
	if !ok {
		logs.Panicf("failed to convert yaml node to a slice: %+v", n.body)
	}
	return result
}

// String returns the Config Node value asserted to a string.
func (n *Node) String() string {
	result, ok := (n.body).(string)
	if !ok {
		logs.Panicf("failed to convert yaml node to a string: %s", n.body)
	}
	return result
}

// SubConfig returns a new Config object with a new sub-root. Similar to
// environment.Config.sub_config in Python.
func (c *Config) SubConfig(path string) *Config {
	root := ""
	if c.root != "" {
		root = c.root + separator
	}

	root += path
	return New(root)
}

// getHelper returnds the Config Node for the given key and path to the config
// location. Similar to local_config.Config._get_helper in Python. This function
// should not panic as it is used by HasValue method.
func (c *Config) getHelper(key string) (*Node, string, error) {
	keyParts := make([]string, 0)
	if c.root != "" {
		keyParts = append(keyParts, c.root)
	}

	if key != "" {
		keyParts = append(keyParts, key)
	}

	if len(keyParts) == 0 {
		return nil, "", errors.New("invalid config key: both key and root are empty")
	}

	fullKey := strings.Join(keyParts, separator)

	path, searchKeys := keyLocation(c.configDir, fullKey)

	if !strings.HasSuffix(path, yamlExt) {
		return nil, "", errors.Errorf("invalid config key: '%s' is a directory", path)
	}

	// Search key in the yaml file.
	value, err := findKey(path, searchKeys)
	if err != nil {
		return nil, "", err
	}

	return value, path, nil
}

// getNode returns a Config Node for the given key. The Node can be either a
// value or a group of values. Similar to local_config.Config.get in Python.
// This function should not panic as it is used by HasValue method.
func (c *Config) getNode(key string) (*Node, error) {
	value, _, err := c.getHelper(key)
	return value, err
}

// GetInt returns an integer value for the given key.
func (c *Config) GetInt(key string) int {
	value, err := c.getNode(key)
	if err != nil {
		logs.Panicf("%+v", err)
	}
	if value == nil {
		logs.Panicf("empty value for the config key '%s'", key)
	}
	return value.Int()
}

// GetMap returns a map of values for the given key.
func (c *Config) GetMap(key string) map[string]interface{} {
	value, err := c.getNode(key)
	if err != nil {
		logs.Panicf("%+v", err)
	}
	if value == nil {
		logs.Panicf("empty value for the config key '%s'", key)
	}
	return value.Map()
}

// GetSlice returns a slice of values for the given key.
func (c *Config) GetSlice(key string) []interface{} {
	value, err := c.getNode(key)
	if err != nil {
		logs.Panicf("%+v", err)
	}
	if value == nil {
		logs.Panicf("empty value for the config key '%s'", key)
	}
	return value.Slice()
}

// GetString returns a string value for the given key.
func (c *Config) GetString(key string) string {
	value, err := c.getNode(key)
	if err != nil {
		logs.Panicf("%+v", err)
	}
	if value == nil {
		logs.Panicf("empty value for the config key '%s'", key)
	}
	return value.String()
}

// GetAbsPath returns absolute path of a key value using the given key name.
// Similar to local_config.Config.get_absolute_path in Python.
func (c *Config) GetAbsPath(key string) string {
	value, yamlPath, err := c.getHelper(key)
	if err != nil {
		logs.Panicf("%+v", err)
	}
	if value == nil {
		logs.Panicf("empty value for the config key '%s'", key)
	}

	subPaths := []string{filepath.Dir(yamlPath)}

	if body := value.Body(); body != nil {
		switch reflect.TypeOf(body).Kind() {
		case reflect.String:
			subPaths = append(subPaths, value.String())
			break
		case reflect.Int:
			subPaths = append(subPaths, strconv.Itoa(value.Int()))
			break
		case reflect.Slice:
			for _, path := range value.Slice() {
				subPaths = append(subPaths, path.(string))
			}
			break
		default:
			logs.Panicf("unhandled value type in a config node: %+v", value)
		}
	} else {
		logs.Panicf("failed to extract path from config for key: '%s'", key)
	}

	return filepath.Join(subPaths...)
}

// HasValue holds if the given key points to a valid value in the config. This
// is useful when working with an optional config key, as Get-methods will panic
// if the value is not present.
func (c *Config) HasValue(key string) bool {
	value, err := c.getNode(key)
	return err == nil && value != nil
}

// Dir returns the path to the configs directory. Similar to
// enrivonment.get_config_directory in Python.
func Dir() string {
	if path := environ.GetValueStr("CONFIG_DIR_OVERRIDE"); path != "" {
		return path
	}

	return "config"
}

// New creates a Config object. Similar to local_config.Config constructor in
// Python.
func New(filePath string) *Config {
	root := filePath
	configDir := Dir()

	// Check that config directory is valid.
	if info, err := os.Stat(configDir); err != nil || !info.IsDir() {
		logs.Panicf("invalid config directory (%s): %+v", configDir, err)
	}

	rootValid := isRootValid(configDir, root)

	if !rootValid {
		logs.Panicf("bad config: '%s'", root)
	}

	return &Config{root, configDir}
}

// NewProjectConfig creates a new default project config. Similar to
// local_config.ProjectConfig constructor in Python.
func NewProjectConfig() *Config {
	return New(projectPath)
}

// SetEnvironment initializes environment variables from the project config.
// Similar to local_config.ProjectConfig.set_environment in Python.
func (c *Config) SetEnvironment() {
	if !c.HasValue("env") {
		return
	}

	env := c.GetMap("env")
	for key, value := range env {
		if environ.HasValue(key) {
			continue
		}

		environ.SetValue(key, value)
	}
}

// loadYaml reads and parses .yaml file contents using the given path to the
// file. Similar to _load_yaml_file in Python.
func loadYaml(filePath string) (*Node, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read yaml config file: '%s'", filePath)
	}

	var body interface{}
	err = yaml.Unmarshal(data, &body)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse yaml config contents: '%s'", filePath)
	}
	return &Node{body}, nil
}

// findKey returns a Config Node for the given key sequence from the given
// config file. Similar to local_config._find_key_in_yaml_file in Python.
func findKey(filePath string, keys []string) (*Node, error) {
	if !fs.PathAccessible(filePath) {
		return nil, nil
	}

	result, err := loadYaml(filePath)
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		// Give the entire yaml file contents.
		return result, nil
	}

	for _, key := range keys {
		cfg := result.Map()
		if cfg[key] == nil {
			result = nil
			break
		}

		result = &Node{cfg[key]}
	}

	return result, nil
}

// keyLocation returns path to the config file and a key sequence for the given
// directory and full key string. Similar to local_config._get_key_location in
// Python.
func keyLocation(dirPath, fullKey string) (string, []string) {
	if fullKey == "" {
		if _, err := os.Stat(dirPath); err == nil {
			return dirPath, make([]string, 0)
		}

		logs.Panicf("invalid config location: '%s'", dirPath)
	}

	keyParts := strings.Split(fullKey, separator)
	searchPath := dirPath
	filenameIdx := -1

	// Find the directory components of the key path.
	for i, key := range keyParts {
		nextPath := filepath.Join(searchPath, key)
		if info, err := os.Stat(nextPath); err == nil && info.IsDir() {
			// Don't allow both a/b/... and a/b.yaml.
			if info, err := os.Stat(searchPath + yamlExt); err == nil && !info.IsDir() {
				logs.Panicf("invalid config key: '%s'", fullKey)
			}
			searchPath = nextPath
		} else {
			// The remainder of the key path is a yaml_filename.key1.key2...
			filenameIdx = i
			break
		}
	}

	if filenameIdx < 0 {
		// The entirety of the key reference a directory.
		return searchPath, make([]string, 0)
	}

	yamlPath := filepath.Join(searchPath, keyParts[filenameIdx]+yamlExt)
	return yamlPath, keyParts[filenameIdx+1:]
}

// isRootValid holds if the given config root is valid and exists for the given
// search path. Similar to local_config._validate_root in Python
func isRootValid(searchPath, root string) bool {
	if root == "" {
		return true
	}

	path, searchKeys := keyLocation(searchPath, root)
	if len(searchKeys) == 0 && !strings.HasSuffix(path, yamlExt) {
		// If the whole searchPath points to a dir, keyLocation verified it exists.
		return true
	}

	// Check that the key exists.
	value, err := findKey(path, searchKeys)
	return err == nil && value != nil
}
