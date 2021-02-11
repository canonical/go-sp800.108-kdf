// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"unicode"
)

var (
	prfs = map[string]string{
		"HMAC_SHA1": "NewHMACPRF(crypto.SHA1)",
		"HMAC_SHA224": "NewHMACPRF(crypto.SHA224)",
		"HMAC_SHA256": "NewHMACPRF(crypto.SHA256)",
		"HMAC_SHA384": "NewHMACPRF(crypto.SHA384)",
		"HMAC_SHA512": "NewHMACPRF(crypto.SHA512)",
	}
)

func scanTokens(data []byte, atEOF bool) (int, []byte, error) {
	// Scan until the end of the line
	lineAdv, tok, err := bufio.ScanLines(data, atEOF)
	switch {
	case err != nil:
		return 0, nil, err
	case lineAdv == 0:
		// Request a new line
		return 0, nil, nil
	case len(tok) == 0:
		// Return a newline as a token
		return lineAdv, []byte{'\n'}, nil
	}

	// Skip space
	adv := strings.IndexFunc(string(tok), func(r rune) bool {
		return !unicode.IsSpace(r)
	})
	if adv < 0 {
		// The rest of the line is all space - request a new one
		return lineAdv, []byte{'\n'}, nil
	}
	tok = tok[adv:]

	// The rest of the line is a comment - request a new one
	if tok[0] == '#' {
		return lineAdv, []byte{'\n'}, nil
	}

	// Find the next delimiter
	i := strings.IndexAny(string(tok), "[]=")
	switch {
	case i == 0:
		tok = []byte{tok[0]}
	case i >= 0:
		tok = tok[:i]
	}

	tok = []byte(strings.TrimSpace(string(tok)))

	return adv + len(tok), tok, nil
}

type testCase map[string]string

type testSuite struct {
	name string
	params map[string]string
	tests []testCase
}

type stateFunc func(string) (stateFunc, error)

type parser struct {
	scanner *bufio.Scanner
	current stateFunc

	suites []*testSuite
	currentSuite *testSuite
	currentTest testCase
	currentName string
}

func (p *parser) handleEndTestCaseParam(tok string) (stateFunc, error) {
	switch {
	case tok == "\n":
		return p.handleStartTestCaseParam, nil
	default:
		return nil, fmt.Errorf("handleEndTestCaseParam: unexpected token %v", tok)
	}
}

func (p *parser) handleTestCaseParam(tok string) (stateFunc, error) {
	p.currentTest[p.currentName] = tok
	return p.handleEndTestCaseParam, nil
}

func (p *parser) handleEndTestSuiteParam2(tok string) (stateFunc, error) {
	switch {
	case tok == "\n":
		return p.handleStartTestSuiteParam, nil
	default:
		return nil, fmt.Errorf("handleEndTestSuiteParam2: unexpected token %v", tok)
	}
}

func (p *parser) handleEndTestSuiteParam(tok string) (stateFunc, error) {
	switch {
	case tok == "]":
		return p.handleEndTestSuiteParam2, nil
	default:
		return nil, fmt.Errorf("handleEndTestSuiteParam: unexpected token %v", tok)
	}
}

func (p *parser) handleEndTestSuiteName(tok string) (stateFunc, error) {
	switch {
	case tok == "]":
		p.currentSuite.name = p.currentName
		return p.handleEndTestSuiteParam(tok)
	case tok == "=":
		return p.handleEqual(tok)
	default:
		return nil, fmt.Errorf("handleEndTestSuiteName: unexpected token %v", tok)
	}
}

func (p *parser) handleTestSuiteParam(tok string) (stateFunc, error) {
	if p.currentSuite.name == "" {
		p.currentSuite.name = tok
	}
	p.currentSuite.params[p.currentName] = tok
	return p.handleEndTestSuiteParam, nil
}

func (p *parser) handleParamValue(tok string) (stateFunc, error) {
	switch {
	case tok == "[" || tok == "]" || tok == "=":
		return nil, fmt.Errorf("handleParamValue: unexpected token %v", tok)
	case tok == "\n" && p.currentTest != nil:
		return p.handleStartTestCaseParam, nil
	case tok == "\n":
		return nil, fmt.Errorf("handleParamValue: unexpected token %v", tok)
	case p.currentTest != nil:
		return p.handleTestCaseParam(tok)
	default:
		return p.handleTestSuiteParam(tok)
	}
}

func (p *parser) handleEqual(tok string) (stateFunc, error) {
	switch {
	case tok == "=":
		return p.handleParamValue, nil
	default:
		return nil, fmt.Errorf("handleEqual: unexpected token %v", tok)
	}
}

func (p *parser) handleParamName(tok string) (stateFunc, error) {
	switch {
	case tok == "\n" || tok == "[" || tok == "]" || tok == "=":
		return nil, fmt.Errorf("handleParamName: unexpected token %v", tok)
	default:
		p.currentName = string(tok)
		return p.handleEqual, nil
	}
}

func (p *parser) handleStartTestCaseParam(tok string) (stateFunc, error) {
	switch {
	case tok == "\n":
		p.currentSuite.tests = append(p.currentSuite.tests, p.currentTest)
		p.currentTest = nil
		return p.start, nil
	case tok == "[" || tok == "]" || tok == "=":
		return nil, fmt.Errorf("handleStartTestCaseParam: unexpected token %v", tok)
	default:
		return p.handleParamName(tok)
	}
}

func (p *parser) handleStartTestSuiteParam2(tok string) (stateFunc, error) {
	switch {
	case tok == "[" || tok == "]" || tok == "=" || tok == "\n":
		return nil, fmt.Errorf("handleStartTestSuiteParam2: unexpected token %v", tok)
	default:
		return p.handleParamName(tok)
	}
}

func (p *parser) handleStartTestSuiteParam(tok string) (stateFunc, error) {
	switch {
	case tok == "\n":
		return p.start, nil
	case tok == "[":
		return p.handleStartTestSuiteParam2, nil
	case tok == "]" || tok == "=":
		return nil, fmt.Errorf("handleStartTestSuiteParam: unexpected token %v", tok)
	default:
		p.currentTest = make(testCase)
		return p.handleStartTestCaseParam(tok)
	}
}

func (p *parser) handleStartTestSuiteName2(tok string) (stateFunc, error) {
	switch {
	case tok == "[" || tok == "]" || tok == "=" || tok == "\n":
		return nil, fmt.Errorf("handleStartTestSuiteName2: unexpected token %v", tok)
	default:
		p.currentName = tok
		return p.handleEndTestSuiteName, nil
	}
}

func (p *parser) handleStartTestSuiteName(tok string) (stateFunc, error) {
	switch {
	case tok == "[":
		return p.handleStartTestSuiteName2, nil
	default:
		return nil, fmt.Errorf("handleStartTestSuiteName: unexpected token %v", tok)
	}
}

func (p *parser) start(tok string) (stateFunc, error) {
	switch {
	case tok == "\n":
		return nil, nil
	case tok == "[":
		p.currentSuite = &testSuite{params: make(map[string]string)}
		p.suites = append(p.suites, p.currentSuite)
		return p.handleStartTestSuiteName(tok)
	case tok == "]" || tok == "=":
		return nil, fmt.Errorf("start: unexpected token %v", tok)
	default:
		if p.currentSuite == nil {
			return nil, fmt.Errorf("start: unexpected token %v (no current suite)", tok)
		}
		p.currentTest = make(testCase)
		return p.handleStartTestCaseParam(tok)
	}
}

func (p *parser) run() error {
	for p.scanner.Scan() {
		next, err := p.current(p.scanner.Text())
		if err != nil {
			return err
		}
		if next != nil {
			p.current = next
		}
	}
	return nil
}

func newParser(r io.Reader) *parser {
	scanner := bufio.NewScanner(r)
	scanner.Split(scanTokens)
	p := &parser{scanner: scanner}
	p.current = p.start
	return p
}

var errSkipSuite = errors.New("")

func generateTests(vectors string, filter map[string]string, emitSuite func(*testSuite, int) error, emitTest func(*testSuite, int, int, testCase) error) error {
	f, err := os.Open(vectors)
	if err != nil {
		return err
	}
	defer f.Close()

	parser := newParser(f)
	if err := parser.run(); err != nil {
		return err
	}

	for i, suite := range parser.suites {
		skip := false
		for k, v := range filter {
			if suite.params[k] != v {
				skip = true
				break
			}
		}

		if skip {
			continue
		}

		if err := emitSuite(suite, i); err != nil {
			if err == errSkipSuite {
				continue
			}
			return err
		}

		for j, test := range suite.tests {
			if err := emitTest(suite, i, j, test); err != nil {
				return err
			}
		}
	}

	return nil
}

type atomicFile struct {
	*os.File
	path string
}

func (f *atomicFile) Commit() error {
	return os.Rename(f.Name(), f.path)
}

func (f *atomicFile) Close() error {
	os.Remove(f.Name())
	return f.File.Close()
}

func newAtomicFile(path string) (*atomicFile, error) {
	f, err := ioutil.TempFile("", "gentest")
	if err != nil {
		return nil, fmt.Errorf("cannot create temporary file: %v", err)
	}
	return &atomicFile{f, path}, nil
}

func run(out io.Writer) error {
	if err := generateTests("testdata/KDFCTR_gen.rsp", map[string]string{"CTRLOCATION":"BEFORE_FIXED", "RLEN":"32_BITS"},
		func(suite *testSuite, _ int) error {
			newPrf, ok := prfs[suite.params["PRF"]]
			if !ok {
				return errSkipSuite
			}

			_, err := fmt.Fprintf(out, `

func (s *kdfSuite) testCounterMode%[1]s(c *C, data *testData) {
	s.testCounterMode(c, %[2]s, data)
}`,
			suite.params["PRF"], newPrf)
			return err
		},
		func(suite *testSuite, _, i int, test testCase) error {
			_, err := fmt.Fprintf(out, `

func (s *kdfSuite) TestCounterMode%[1]s_%[2]d(c *C) {
	s.testCounterMode%[1]s(c, &testData{
		key: decodeHexString(c, "%[3]s"),
		fixed: decodeHexString(c, "%[4]s"),
		bitLength: %[5]s,
		expected: decodeHexString(c, "%[6]s"),
	})
}`,
			suite.params["PRF"], i, test["KI"], test["FixedInputData"], test["L"], test["KO"])
			return err
		},
	); err != nil {
		return err
	}

	if err := generateTests("testdata/FeedbackModenocounter/KDFFeedback_gen.rsp", nil,
		func(suite *testSuite, _ int) error {
			newPrf, ok := prfs[suite.params["PRF"]]
			if !ok {
				return errSkipSuite
			}

			_, err := fmt.Fprintf(out, `

func (s *kdfSuite) testFeedbackModeNoCounter%[1]s(c *C, data *testData) {
	s.testFeedbackMode(c, %[2]s, data, false)
}`,
			suite.params["PRF"], newPrf)
			return err
		},
		func(suite *testSuite, _, i int, test testCase) error {
			_, err := fmt.Fprintf(out, `

func (s *kdfSuite) TestFeedbackModeNoCounter%[1]s_%[2]d(c *C) {
	s.testFeedbackModeNoCounter%[1]s(c, &testData{
		key: decodeHexString(c, "%[3]s"),
		fixed: decodeHexString(c, "%[4]s"),
		iv: decodeHexString(c, "%[5]s"),
		bitLength: %[6]s,
		expected: decodeHexString(c, "%[7]s"),
	})
}`,
			suite.params["PRF"], i, test["KI"], test["FixedInputData"], test["IV"], test["L"], test["KO"])
			return err
		},
	); err != nil {
		return err
	}

	if err := generateTests("testdata/FeedbackModeNOzeroiv/KDFFeedback_gen.rsp", map[string]string{"CTRLOCATION":"AFTER_ITER", "RLEN":"32_BITS"},
		func(suite *testSuite, _ int) error {
			newPrf, ok := prfs[suite.params["PRF"]]
			if !ok {
				return errSkipSuite
			}

			_, err := fmt.Fprintf(out, `

func (s *kdfSuite) testFeedbackModeNoZeroIV%[1]s(c *C, data *testData) {
	s.testFeedbackMode(c, %[2]s, data, true)
}`,
			suite.params["PRF"], newPrf)
			return err
		},
		func(suite *testSuite, _, i int, test testCase) error {
			_, err := fmt.Fprintf(out, `

func (s *kdfSuite) TestFeedbackModeNoZeroIV%[1]s_%[2]d(c *C) {
	s.testFeedbackModeNoZeroIV%[1]s(c, &testData{
		key: decodeHexString(c, "%[3]s"),
		fixed: decodeHexString(c, "%[4]s"),
		iv: decodeHexString(c, "%[5]s"),
		bitLength: %[6]s,
		expected: decodeHexString(c, "%[7]s"),
	})
}`,
			suite.params["PRF"], i, test["KI"], test["FixedInputData"], test["IV"], test["L"], test["KO"])
			return err
		},
	); err != nil {
		return err
	}

	if err := generateTests("testdata/FeedbackModewzeroiv/KDFFeedback_gen.rsp", map[string]string{"CTRLOCATION":"AFTER_ITER", "RLEN":"32_BITS"},
		func(suite *testSuite, _ int) error {
			newPrf, ok := prfs[suite.params["PRF"]]
			if !ok {
				return errSkipSuite
			}

			_, err := fmt.Fprintf(out, `

func (s *kdfSuite) testFeedbackModeZeroIV%[1]s(c *C, data *testData) {
	s.testFeedbackMode(c, %[2]s, data, true)
}`,
			suite.params["PRF"], newPrf)
			return err
		},
		func(suite *testSuite, _, i int, test testCase) error {
			_, err := fmt.Fprintf(out, `

func (s *kdfSuite) TestFeedbackModeZeroIV%[1]s_%[2]d(c *C) {
	s.testFeedbackModeZeroIV%[1]s(c, &testData{
		key: decodeHexString(c, "%[3]s"),
		fixed: decodeHexString(c, "%[4]s"),
		iv: decodeHexString(c, "%[5]s"),
		bitLength: %[6]s,
		expected: decodeHexString(c, "%[7]s"),
	})
}`,
			suite.params["PRF"], i, test["KI"], test["FixedInputData"], test["IV"], test["L"], test["KO"])
			return err
		},
	); err != nil {
		return err
	}

	if err := generateTests("testdata/PipelineModewithCounter/KDFDblPipeline_gen.rsp", map[string]string{"CTRLOCATION":"AFTER_ITER", "RLEN":"32_BITS"},
		func(suite *testSuite, _ int) error {
			newPrf, ok := prfs[suite.params["PRF"]]
			if !ok {
				return errSkipSuite
			}

			_, err := fmt.Fprintf(out, `

func (s *kdfSuite) testPipelineMode%[1]s(c *C, data *testData) {
	s.testPipelineMode(c, %[2]s, data, true)
}`,
			suite.params["PRF"], newPrf)
			return err
		},
		func(suite *testSuite, _, i int, test testCase) error {
			_, err := fmt.Fprintf(out, `

func (s *kdfSuite) TestPipelineMode%[1]s_%[2]d(c *C) {
	s.testPipelineMode%[1]s(c, &testData{
		key: decodeHexString(c, "%[3]s"),
		fixed: decodeHexString(c, "%[4]s"),
		bitLength: %[5]s,
		expected: decodeHexString(c, "%[6]s"),
	})
}`,
			suite.params["PRF"], i, test["KI"], test["FixedInputData"], test["L"], test["KO"])
			return err
		},
	); err != nil {
		return err
	}

	if err := generateTests("testdata/PipelineModeWOCounterr/KDFDblPipeline_gen.rsp", nil,
		func(suite *testSuite, _ int) error {
			newPrf, ok := prfs[suite.params["PRF"]]
			if !ok {
				return errSkipSuite
			}

			_, err := fmt.Fprintf(out, `

func (s *kdfSuite) testPipelineModeNoCounter%[1]s(c *C, data *testData) {
	s.testPipelineMode(c, %[2]s, data, false)
}`,
			suite.params["PRF"], newPrf)
			return err
		},
		func(suite *testSuite, _, i int, test testCase) error {
			_, err := fmt.Fprintf(out, `

func (s *kdfSuite) TestPipelineModeNoCounter%[1]s_%[2]d(c *C) {
	s.testPipelineModeNoCounter%[1]s(c, &testData{
		key: decodeHexString(c, "%[3]s"),
		fixed: decodeHexString(c, "%[4]s"),
		bitLength: %[5]s,
		expected: decodeHexString(c, "%[6]s"),
	})
}`,
			suite.params["PRF"], i, test["KI"], test["FixedInputData"], test["L"], test["KO"])
			return err
		},
	); err != nil {
		return err
	}

	return nil
}

func main() {
	tmpl, err := os.Open("testdata/kdf_test.go.in")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open template file: %v\n")
		os.Exit(1)
	}

	dst, err := newAtomicFile("kdf_test.go")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open destination file: %v\n")
		os.Exit(1)
	}

	if _, err := io.Copy(dst, tmpl); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot copy template: %v\n", err)
		dst.Close()
		os.Exit(1)
	}

	if err := run(dst); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		dst.Close()
		os.Exit(1)
	}

	if err := dst.Commit(); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot commit destination file: %v\n")
		dst.Close()
		os.Exit(1)
	}

	dst.Close()
}
