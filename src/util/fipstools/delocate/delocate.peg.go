package main

import (
	"fmt"
	"math"
	"sort"
	"strconv"
)

const endSymbol rune = 1114112

/* The rule types inferred from the grammar are below. */
type pegRule uint8

const (
	ruleUnknown pegRule = iota
	ruleAsmFile
	ruleStatement
	ruleGlobalDirective
	ruleDirective
	ruleDirectiveName
	ruleLocationDirective
	ruleFileDirective
	ruleLocDirective
	ruleArgs
	ruleArg
	ruleQuotedArg
	ruleQuotedText
	ruleLabelContainingDirective
	ruleLabelContainingDirectiveName
	ruleSymbolArgs
	ruleSymbolShift
	ruleSymbolArg
	ruleOpenParen
	ruleCloseParen
	ruleSymbolType
	ruleDot
	ruleTCMarker
	ruleEscapedChar
	ruleWS
	ruleComment
	ruleLabel
	ruleSymbolName
	ruleLocalSymbol
	ruleLocalLabel
	ruleLocalLabelRef
	ruleInstruction
	ruleInstructionName
	ruleInstructionArg
	ruleGOTLocation
	ruleGOTSymbolOffset
	ruleAVX512Token
	ruleTOCRefHigh
	ruleTOCRefLow
	ruleIndirectionIndicator
	ruleRegisterOrConstant
	ruleARMConstantTweak
	ruleARMRegister
	ruleARMVectorRegister
	ruleMemoryRef
	ruleSymbolRef
	ruleLow12BitsSymbolRef
	ruleARMBaseIndexScale
	ruleARMGOTLow12
	ruleARMPostincrement
	ruleBaseIndexScale
	ruleOperator
	ruleOffset
	ruleSection
	ruleSegmentRegister
)

var rul3s = [...]string{
	"Unknown",
	"AsmFile",
	"Statement",
	"GlobalDirective",
	"Directive",
	"DirectiveName",
	"LocationDirective",
	"FileDirective",
	"LocDirective",
	"Args",
	"Arg",
	"QuotedArg",
	"QuotedText",
	"LabelContainingDirective",
	"LabelContainingDirectiveName",
	"SymbolArgs",
	"SymbolShift",
	"SymbolArg",
	"OpenParen",
	"CloseParen",
	"SymbolType",
	"Dot",
	"TCMarker",
	"EscapedChar",
	"WS",
	"Comment",
	"Label",
	"SymbolName",
	"LocalSymbol",
	"LocalLabel",
	"LocalLabelRef",
	"Instruction",
	"InstructionName",
	"InstructionArg",
	"GOTLocation",
	"GOTSymbolOffset",
	"AVX512Token",
	"TOCRefHigh",
	"TOCRefLow",
	"IndirectionIndicator",
	"RegisterOrConstant",
	"ARMConstantTweak",
	"ARMRegister",
	"ARMVectorRegister",
	"MemoryRef",
	"SymbolRef",
	"Low12BitsSymbolRef",
	"ARMBaseIndexScale",
	"ARMGOTLow12",
	"ARMPostincrement",
	"BaseIndexScale",
	"Operator",
	"Offset",
	"Section",
	"SegmentRegister",
}

type token32 struct {
	pegRule
	begin, end uint32
}

func (t *token32) String() string {
	return fmt.Sprintf("\x1B[34m%v\x1B[m %v %v", rul3s[t.pegRule], t.begin, t.end)
}

type node32 struct {
	token32
	up, next *node32
}

func (node *node32) print(pretty bool, buffer string) {
	var print func(node *node32, depth int)
	print = func(node *node32, depth int) {
		for node != nil {
			for c := 0; c < depth; c++ {
				fmt.Printf(" ")
			}
			rule := rul3s[node.pegRule]
			quote := strconv.Quote(string(([]rune(buffer)[node.begin:node.end])))
			if !pretty {
				fmt.Printf("%v %v\n", rule, quote)
			} else {
				fmt.Printf("\x1B[34m%v\x1B[m %v\n", rule, quote)
			}
			if node.up != nil {
				print(node.up, depth+1)
			}
			node = node.next
		}
	}
	print(node, 0)
}

func (node *node32) Print(buffer string) {
	node.print(false, buffer)
}

func (node *node32) PrettyPrint(buffer string) {
	node.print(true, buffer)
}

type tokens32 struct {
	tree []token32
}

func (t *tokens32) Trim(length uint32) {
	t.tree = t.tree[:length]
}

func (t *tokens32) Print() {
	for _, token := range t.tree {
		fmt.Println(token.String())
	}
}

func (t *tokens32) AST() *node32 {
	type element struct {
		node *node32
		down *element
	}
	tokens := t.Tokens()
	var stack *element
	for _, token := range tokens {
		if token.begin == token.end {
			continue
		}
		node := &node32{token32: token}
		for stack != nil && stack.node.begin >= token.begin && stack.node.end <= token.end {
			stack.node.next = node.up
			node.up = stack.node
			stack = stack.down
		}
		stack = &element{node: node, down: stack}
	}
	if stack != nil {
		return stack.node
	}
	return nil
}

func (t *tokens32) PrintSyntaxTree(buffer string) {
	t.AST().Print(buffer)
}

func (t *tokens32) PrettyPrintSyntaxTree(buffer string) {
	t.AST().PrettyPrint(buffer)
}

func (t *tokens32) Add(rule pegRule, begin, end, index uint32) {
	if tree := t.tree; int(index) >= len(tree) {
		expanded := make([]token32, 2*len(tree))
		copy(expanded, tree)
		t.tree = expanded
	}
	t.tree[index] = token32{
		pegRule: rule,
		begin:   begin,
		end:     end,
	}
}

func (t *tokens32) Tokens() []token32 {
	return t.tree
}

type Asm struct {
	Buffer string
	buffer []rune
	rules  [55]func() bool
	parse  func(rule ...int) error
	reset  func()
	Pretty bool
	tokens32
}

func (p *Asm) Parse(rule ...int) error {
	return p.parse(rule...)
}

func (p *Asm) Reset() {
	p.reset()
}

type textPosition struct {
	line, symbol int
}

type textPositionMap map[int]textPosition

func translatePositions(buffer []rune, positions []int) textPositionMap {
	length, translations, j, line, symbol := len(positions), make(textPositionMap, len(positions)), 0, 1, 0
	sort.Ints(positions)

search:
	for i, c := range buffer {
		if c == '\n' {
			line, symbol = line+1, 0
		} else {
			symbol++
		}
		if i == positions[j] {
			translations[positions[j]] = textPosition{line, symbol}
			for j++; j < length; j++ {
				if i != positions[j] {
					continue search
				}
			}
			break search
		}
	}

	return translations
}

type parseError struct {
	p   *Asm
	max token32
}

func (e *parseError) Error() string {
	tokens, error := []token32{e.max}, "\n"
	positions, p := make([]int, 2*len(tokens)), 0
	for _, token := range tokens {
		positions[p], p = int(token.begin), p+1
		positions[p], p = int(token.end), p+1
	}
	translations := translatePositions(e.p.buffer, positions)
	format := "parse error near %v (line %v symbol %v - line %v symbol %v):\n%v\n"
	if e.p.Pretty {
		format = "parse error near \x1B[34m%v\x1B[m (line %v symbol %v - line %v symbol %v):\n%v\n"
	}
	for _, token := range tokens {
		begin, end := int(token.begin), int(token.end)
		error += fmt.Sprintf(format,
			rul3s[token.pegRule],
			translations[begin].line, translations[begin].symbol,
			translations[end].line, translations[end].symbol,
			strconv.Quote(string(e.p.buffer[begin:end])))
	}

	return error
}

func (p *Asm) PrintSyntaxTree() {
	if p.Pretty {
		p.tokens32.PrettyPrintSyntaxTree(p.Buffer)
	} else {
		p.tokens32.PrintSyntaxTree(p.Buffer)
	}
}

func (p *Asm) Init() {
	var (
		max                  token32
		position, tokenIndex uint32
		buffer               []rune
	)
	p.reset = func() {
		max = token32{}
		position, tokenIndex = 0, 0

		p.buffer = []rune(p.Buffer)
		if len(p.buffer) == 0 || p.buffer[len(p.buffer)-1] != endSymbol {
			p.buffer = append(p.buffer, endSymbol)
		}
		buffer = p.buffer
	}
	p.reset()

	_rules := p.rules
	tree := tokens32{tree: make([]token32, math.MaxInt16)}
	p.parse = func(rule ...int) error {
		r := 1
		if len(rule) > 0 {
			r = rule[0]
		}
		matches := p.rules[r]()
		p.tokens32 = tree
		if matches {
			p.Trim(tokenIndex)
			return nil
		}
		return &parseError{p, max}
	}

	add := func(rule pegRule, begin uint32) {
		tree.Add(rule, begin, position, tokenIndex)
		tokenIndex++
		if begin != position && position > max.end {
			max = token32{rule, begin, position}
		}
	}

	matchDot := func() bool {
		if buffer[position] != endSymbol {
			position++
			return true
		}
		return false
	}

	/*matchChar := func(c byte) bool {
		if buffer[position] == c {
			position++
			return true
		}
		return false
	}*/

	/*matchRange := func(lower byte, upper byte) bool {
		if c := buffer[position]; c >= lower && c <= upper {
			position++
			return true
		}
		return false
	}*/

	_rules = [...]func() bool{
		nil,
		/* 0 AsmFile <- <(Statement* !.)> */
		func() bool {
			position0, tokenIndex0 := position, tokenIndex
			{
				position1 := position
			l2:
				{
					position3, tokenIndex3 := position, tokenIndex
					if !_rules[ruleStatement]() {
						goto l3
					}
					goto l2
				l3:
					position, tokenIndex = position3, tokenIndex3
				}
				{
					position4, tokenIndex4 := position, tokenIndex
					if !matchDot() {
						goto l4
					}
					goto l0
				l4:
					position, tokenIndex = position4, tokenIndex4
				}
				add(ruleAsmFile, position1)
			}
			return true
		l0:
			position, tokenIndex = position0, tokenIndex0
			return false
		},
		/* 1 Statement <- <(WS? (Label / ((GlobalDirective / LocationDirective / LabelContainingDirective / Instruction / Directive / Comment / ) WS? ((Comment? '\n') / ';'))))> */
		func() bool {
			position5, tokenIndex5 := position, tokenIndex
			{
				position6 := position
				{
					position7, tokenIndex7 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l7
					}
					goto l8
				l7:
					position, tokenIndex = position7, tokenIndex7
				}
			l8:
				{
					position9, tokenIndex9 := position, tokenIndex
					if !_rules[ruleLabel]() {
						goto l10
					}
					goto l9
				l10:
					position, tokenIndex = position9, tokenIndex9
					{
						position11, tokenIndex11 := position, tokenIndex
						if !_rules[ruleGlobalDirective]() {
							goto l12
						}
						goto l11
					l12:
						position, tokenIndex = position11, tokenIndex11
						if !_rules[ruleLocationDirective]() {
							goto l13
						}
						goto l11
					l13:
						position, tokenIndex = position11, tokenIndex11
						if !_rules[ruleLabelContainingDirective]() {
							goto l14
						}
						goto l11
					l14:
						position, tokenIndex = position11, tokenIndex11
						if !_rules[ruleInstruction]() {
							goto l15
						}
						goto l11
					l15:
						position, tokenIndex = position11, tokenIndex11
						if !_rules[ruleDirective]() {
							goto l16
						}
						goto l11
					l16:
						position, tokenIndex = position11, tokenIndex11
						if !_rules[ruleComment]() {
							goto l17
						}
						goto l11
					l17:
						position, tokenIndex = position11, tokenIndex11
					}
				l11:
					{
						position18, tokenIndex18 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l18
						}
						goto l19
					l18:
						position, tokenIndex = position18, tokenIndex18
					}
				l19:
					{
						position20, tokenIndex20 := position, tokenIndex
						{
							position22, tokenIndex22 := position, tokenIndex
							if !_rules[ruleComment]() {
								goto l22
							}
							goto l23
						l22:
							position, tokenIndex = position22, tokenIndex22
						}
					l23:
						if buffer[position] != rune('\n') {
							goto l21
						}
						position++
						goto l20
					l21:
						position, tokenIndex = position20, tokenIndex20
						if buffer[position] != rune(';') {
							goto l5
						}
						position++
					}
				l20:
				}
			l9:
				add(ruleStatement, position6)
			}
			return true
		l5:
			position, tokenIndex = position5, tokenIndex5
			return false
		},
		/* 2 GlobalDirective <- <((('.' ('g' / 'G') ('l' / 'L') ('o' / 'O') ('b' / 'B') ('a' / 'A') ('l' / 'L')) / ('.' ('g' / 'G') ('l' / 'L') ('o' / 'O') ('b' / 'B') ('l' / 'L'))) WS SymbolName)> */
		func() bool {
			position24, tokenIndex24 := position, tokenIndex
			{
				position25 := position
				{
					position26, tokenIndex26 := position, tokenIndex
					if buffer[position] != rune('.') {
						goto l27
					}
					position++
					{
						position28, tokenIndex28 := position, tokenIndex
						if buffer[position] != rune('g') {
							goto l29
						}
						position++
						goto l28
					l29:
						position, tokenIndex = position28, tokenIndex28
						if buffer[position] != rune('G') {
							goto l27
						}
						position++
					}
				l28:
					{
						position30, tokenIndex30 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l31
						}
						position++
						goto l30
					l31:
						position, tokenIndex = position30, tokenIndex30
						if buffer[position] != rune('L') {
							goto l27
						}
						position++
					}
				l30:
					{
						position32, tokenIndex32 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l33
						}
						position++
						goto l32
					l33:
						position, tokenIndex = position32, tokenIndex32
						if buffer[position] != rune('O') {
							goto l27
						}
						position++
					}
				l32:
					{
						position34, tokenIndex34 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l35
						}
						position++
						goto l34
					l35:
						position, tokenIndex = position34, tokenIndex34
						if buffer[position] != rune('B') {
							goto l27
						}
						position++
					}
				l34:
					{
						position36, tokenIndex36 := position, tokenIndex
						if buffer[position] != rune('a') {
							goto l37
						}
						position++
						goto l36
					l37:
						position, tokenIndex = position36, tokenIndex36
						if buffer[position] != rune('A') {
							goto l27
						}
						position++
					}
				l36:
					{
						position38, tokenIndex38 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l39
						}
						position++
						goto l38
					l39:
						position, tokenIndex = position38, tokenIndex38
						if buffer[position] != rune('L') {
							goto l27
						}
						position++
					}
				l38:
					goto l26
				l27:
					position, tokenIndex = position26, tokenIndex26
					if buffer[position] != rune('.') {
						goto l24
					}
					position++
					{
						position40, tokenIndex40 := position, tokenIndex
						if buffer[position] != rune('g') {
							goto l41
						}
						position++
						goto l40
					l41:
						position, tokenIndex = position40, tokenIndex40
						if buffer[position] != rune('G') {
							goto l24
						}
						position++
					}
				l40:
					{
						position42, tokenIndex42 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l43
						}
						position++
						goto l42
					l43:
						position, tokenIndex = position42, tokenIndex42
						if buffer[position] != rune('L') {
							goto l24
						}
						position++
					}
				l42:
					{
						position44, tokenIndex44 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l45
						}
						position++
						goto l44
					l45:
						position, tokenIndex = position44, tokenIndex44
						if buffer[position] != rune('O') {
							goto l24
						}
						position++
					}
				l44:
					{
						position46, tokenIndex46 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l47
						}
						position++
						goto l46
					l47:
						position, tokenIndex = position46, tokenIndex46
						if buffer[position] != rune('B') {
							goto l24
						}
						position++
					}
				l46:
					{
						position48, tokenIndex48 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l49
						}
						position++
						goto l48
					l49:
						position, tokenIndex = position48, tokenIndex48
						if buffer[position] != rune('L') {
							goto l24
						}
						position++
					}
				l48:
				}
			l26:
				if !_rules[ruleWS]() {
					goto l24
				}
				if !_rules[ruleSymbolName]() {
					goto l24
				}
				add(ruleGlobalDirective, position25)
			}
			return true
		l24:
			position, tokenIndex = position24, tokenIndex24
			return false
		},
		/* 3 Directive <- <('.' DirectiveName (WS Args)?)> */
		func() bool {
			position50, tokenIndex50 := position, tokenIndex
			{
				position51 := position
				if buffer[position] != rune('.') {
					goto l50
				}
				position++
				if !_rules[ruleDirectiveName]() {
					goto l50
				}
				{
					position52, tokenIndex52 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l52
					}
					if !_rules[ruleArgs]() {
						goto l52
					}
					goto l53
				l52:
					position, tokenIndex = position52, tokenIndex52
				}
			l53:
				add(ruleDirective, position51)
			}
			return true
		l50:
			position, tokenIndex = position50, tokenIndex50
			return false
		},
		/* 4 DirectiveName <- <([a-z] / [A-Z] / ([0-9] / [0-9]) / '_')+> */
		func() bool {
			position54, tokenIndex54 := position, tokenIndex
			{
				position55 := position
				{
					position58, tokenIndex58 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l59
					}
					position++
					goto l58
				l59:
					position, tokenIndex = position58, tokenIndex58
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l60
					}
					position++
					goto l58
				l60:
					position, tokenIndex = position58, tokenIndex58
					{
						position62, tokenIndex62 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l63
						}
						position++
						goto l62
					l63:
						position, tokenIndex = position62, tokenIndex62
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l61
						}
						position++
					}
				l62:
					goto l58
				l61:
					position, tokenIndex = position58, tokenIndex58
					if buffer[position] != rune('_') {
						goto l54
					}
					position++
				}
			l58:
			l56:
				{
					position57, tokenIndex57 := position, tokenIndex
					{
						position64, tokenIndex64 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l65
						}
						position++
						goto l64
					l65:
						position, tokenIndex = position64, tokenIndex64
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l66
						}
						position++
						goto l64
					l66:
						position, tokenIndex = position64, tokenIndex64
						{
							position68, tokenIndex68 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l69
							}
							position++
							goto l68
						l69:
							position, tokenIndex = position68, tokenIndex68
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l67
							}
							position++
						}
					l68:
						goto l64
					l67:
						position, tokenIndex = position64, tokenIndex64
						if buffer[position] != rune('_') {
							goto l57
						}
						position++
					}
				l64:
					goto l56
				l57:
					position, tokenIndex = position57, tokenIndex57
				}
				add(ruleDirectiveName, position55)
			}
			return true
		l54:
			position, tokenIndex = position54, tokenIndex54
			return false
		},
		/* 5 LocationDirective <- <(FileDirective / LocDirective)> */
		func() bool {
			position70, tokenIndex70 := position, tokenIndex
			{
				position71 := position
				{
					position72, tokenIndex72 := position, tokenIndex
					if !_rules[ruleFileDirective]() {
						goto l73
					}
					goto l72
				l73:
					position, tokenIndex = position72, tokenIndex72
					if !_rules[ruleLocDirective]() {
						goto l70
					}
				}
			l72:
				add(ruleLocationDirective, position71)
			}
			return true
		l70:
			position, tokenIndex = position70, tokenIndex70
			return false
		},
		/* 6 FileDirective <- <('.' ('f' / 'F') ('i' / 'I') ('l' / 'L') ('e' / 'E') WS (!('#' / '\n') .)+)> */
		func() bool {
			position74, tokenIndex74 := position, tokenIndex
			{
				position75 := position
				if buffer[position] != rune('.') {
					goto l74
				}
				position++
				{
					position76, tokenIndex76 := position, tokenIndex
					if buffer[position] != rune('f') {
						goto l77
					}
					position++
					goto l76
				l77:
					position, tokenIndex = position76, tokenIndex76
					if buffer[position] != rune('F') {
						goto l74
					}
					position++
				}
			l76:
				{
					position78, tokenIndex78 := position, tokenIndex
					if buffer[position] != rune('i') {
						goto l79
					}
					position++
					goto l78
				l79:
					position, tokenIndex = position78, tokenIndex78
					if buffer[position] != rune('I') {
						goto l74
					}
					position++
				}
			l78:
				{
					position80, tokenIndex80 := position, tokenIndex
					if buffer[position] != rune('l') {
						goto l81
					}
					position++
					goto l80
				l81:
					position, tokenIndex = position80, tokenIndex80
					if buffer[position] != rune('L') {
						goto l74
					}
					position++
				}
			l80:
				{
					position82, tokenIndex82 := position, tokenIndex
					if buffer[position] != rune('e') {
						goto l83
					}
					position++
					goto l82
				l83:
					position, tokenIndex = position82, tokenIndex82
					if buffer[position] != rune('E') {
						goto l74
					}
					position++
				}
			l82:
				if !_rules[ruleWS]() {
					goto l74
				}
				{
					position86, tokenIndex86 := position, tokenIndex
					{
						position87, tokenIndex87 := position, tokenIndex
						if buffer[position] != rune('#') {
							goto l88
						}
						position++
						goto l87
					l88:
						position, tokenIndex = position87, tokenIndex87
						if buffer[position] != rune('\n') {
							goto l86
						}
						position++
					}
				l87:
					goto l74
				l86:
					position, tokenIndex = position86, tokenIndex86
				}
				if !matchDot() {
					goto l74
				}
			l84:
				{
					position85, tokenIndex85 := position, tokenIndex
					{
						position89, tokenIndex89 := position, tokenIndex
						{
							position90, tokenIndex90 := position, tokenIndex
							if buffer[position] != rune('#') {
								goto l91
							}
							position++
							goto l90
						l91:
							position, tokenIndex = position90, tokenIndex90
							if buffer[position] != rune('\n') {
								goto l89
							}
							position++
						}
					l90:
						goto l85
					l89:
						position, tokenIndex = position89, tokenIndex89
					}
					if !matchDot() {
						goto l85
					}
					goto l84
				l85:
					position, tokenIndex = position85, tokenIndex85
				}
				add(ruleFileDirective, position75)
			}
			return true
		l74:
			position, tokenIndex = position74, tokenIndex74
			return false
		},
		/* 7 LocDirective <- <('.' ('l' / 'L') ('o' / 'O') ('c' / 'C') WS (!('#' / '/' / '\n') .)+)> */
		func() bool {
			position92, tokenIndex92 := position, tokenIndex
			{
				position93 := position
				if buffer[position] != rune('.') {
					goto l92
				}
				position++
				{
					position94, tokenIndex94 := position, tokenIndex
					if buffer[position] != rune('l') {
						goto l95
					}
					position++
					goto l94
				l95:
					position, tokenIndex = position94, tokenIndex94
					if buffer[position] != rune('L') {
						goto l92
					}
					position++
				}
			l94:
				{
					position96, tokenIndex96 := position, tokenIndex
					if buffer[position] != rune('o') {
						goto l97
					}
					position++
					goto l96
				l97:
					position, tokenIndex = position96, tokenIndex96
					if buffer[position] != rune('O') {
						goto l92
					}
					position++
				}
			l96:
				{
					position98, tokenIndex98 := position, tokenIndex
					if buffer[position] != rune('c') {
						goto l99
					}
					position++
					goto l98
				l99:
					position, tokenIndex = position98, tokenIndex98
					if buffer[position] != rune('C') {
						goto l92
					}
					position++
				}
			l98:
				if !_rules[ruleWS]() {
					goto l92
				}
				{
					position102, tokenIndex102 := position, tokenIndex
					{
						position103, tokenIndex103 := position, tokenIndex
						if buffer[position] != rune('#') {
							goto l104
						}
						position++
						goto l103
					l104:
						position, tokenIndex = position103, tokenIndex103
						if buffer[position] != rune('/') {
							goto l105
						}
						position++
						goto l103
					l105:
						position, tokenIndex = position103, tokenIndex103
						if buffer[position] != rune('\n') {
							goto l102
						}
						position++
					}
				l103:
					goto l92
				l102:
					position, tokenIndex = position102, tokenIndex102
				}
				if !matchDot() {
					goto l92
				}
			l100:
				{
					position101, tokenIndex101 := position, tokenIndex
					{
						position106, tokenIndex106 := position, tokenIndex
						{
							position107, tokenIndex107 := position, tokenIndex
							if buffer[position] != rune('#') {
								goto l108
							}
							position++
							goto l107
						l108:
							position, tokenIndex = position107, tokenIndex107
							if buffer[position] != rune('/') {
								goto l109
							}
							position++
							goto l107
						l109:
							position, tokenIndex = position107, tokenIndex107
							if buffer[position] != rune('\n') {
								goto l106
							}
							position++
						}
					l107:
						goto l101
					l106:
						position, tokenIndex = position106, tokenIndex106
					}
					if !matchDot() {
						goto l101
					}
					goto l100
				l101:
					position, tokenIndex = position101, tokenIndex101
				}
				add(ruleLocDirective, position93)
			}
			return true
		l92:
			position, tokenIndex = position92, tokenIndex92
			return false
		},
		/* 8 Args <- <(Arg (WS? ',' WS? Arg)*)> */
		func() bool {
			position110, tokenIndex110 := position, tokenIndex
			{
				position111 := position
				if !_rules[ruleArg]() {
					goto l110
				}
			l112:
				{
					position113, tokenIndex113 := position, tokenIndex
					{
						position114, tokenIndex114 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l114
						}
						goto l115
					l114:
						position, tokenIndex = position114, tokenIndex114
					}
				l115:
					if buffer[position] != rune(',') {
						goto l113
					}
					position++
					{
						position116, tokenIndex116 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l116
						}
						goto l117
					l116:
						position, tokenIndex = position116, tokenIndex116
					}
				l117:
					if !_rules[ruleArg]() {
						goto l113
					}
					goto l112
				l113:
					position, tokenIndex = position113, tokenIndex113
				}
				add(ruleArgs, position111)
			}
			return true
		l110:
			position, tokenIndex = position110, tokenIndex110
			return false
		},
		/* 9 Arg <- <(QuotedArg / ([0-9] / [0-9] / ([a-z] / [A-Z]) / '%' / '+' / '-' / '*' / '_' / '@' / '.')*)> */
		func() bool {
			{
				position119 := position
				{
					position120, tokenIndex120 := position, tokenIndex
					if !_rules[ruleQuotedArg]() {
						goto l121
					}
					goto l120
				l121:
					position, tokenIndex = position120, tokenIndex120
				l122:
					{
						position123, tokenIndex123 := position, tokenIndex
						{
							position124, tokenIndex124 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l125
							}
							position++
							goto l124
						l125:
							position, tokenIndex = position124, tokenIndex124
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l126
							}
							position++
							goto l124
						l126:
							position, tokenIndex = position124, tokenIndex124
							{
								position128, tokenIndex128 := position, tokenIndex
								if c := buffer[position]; c < rune('a') || c > rune('z') {
									goto l129
								}
								position++
								goto l128
							l129:
								position, tokenIndex = position128, tokenIndex128
								if c := buffer[position]; c < rune('A') || c > rune('Z') {
									goto l127
								}
								position++
							}
						l128:
							goto l124
						l127:
							position, tokenIndex = position124, tokenIndex124
							if buffer[position] != rune('%') {
								goto l130
							}
							position++
							goto l124
						l130:
							position, tokenIndex = position124, tokenIndex124
							if buffer[position] != rune('+') {
								goto l131
							}
							position++
							goto l124
						l131:
							position, tokenIndex = position124, tokenIndex124
							if buffer[position] != rune('-') {
								goto l132
							}
							position++
							goto l124
						l132:
							position, tokenIndex = position124, tokenIndex124
							if buffer[position] != rune('*') {
								goto l133
							}
							position++
							goto l124
						l133:
							position, tokenIndex = position124, tokenIndex124
							if buffer[position] != rune('_') {
								goto l134
							}
							position++
							goto l124
						l134:
							position, tokenIndex = position124, tokenIndex124
							if buffer[position] != rune('@') {
								goto l135
							}
							position++
							goto l124
						l135:
							position, tokenIndex = position124, tokenIndex124
							if buffer[position] != rune('.') {
								goto l123
							}
							position++
						}
					l124:
						goto l122
					l123:
						position, tokenIndex = position123, tokenIndex123
					}
				}
			l120:
				add(ruleArg, position119)
			}
			return true
		},
		/* 10 QuotedArg <- <('"' QuotedText '"')> */
		func() bool {
			position136, tokenIndex136 := position, tokenIndex
			{
				position137 := position
				if buffer[position] != rune('"') {
					goto l136
				}
				position++
				if !_rules[ruleQuotedText]() {
					goto l136
				}
				if buffer[position] != rune('"') {
					goto l136
				}
				position++
				add(ruleQuotedArg, position137)
			}
			return true
		l136:
			position, tokenIndex = position136, tokenIndex136
			return false
		},
		/* 11 QuotedText <- <(EscapedChar / (!'"' .))*> */
		func() bool {
			{
				position139 := position
			l140:
				{
					position141, tokenIndex141 := position, tokenIndex
					{
						position142, tokenIndex142 := position, tokenIndex
						if !_rules[ruleEscapedChar]() {
							goto l143
						}
						goto l142
					l143:
						position, tokenIndex = position142, tokenIndex142
						{
							position144, tokenIndex144 := position, tokenIndex
							if buffer[position] != rune('"') {
								goto l144
							}
							position++
							goto l141
						l144:
							position, tokenIndex = position144, tokenIndex144
						}
						if !matchDot() {
							goto l141
						}
					}
				l142:
					goto l140
				l141:
					position, tokenIndex = position141, tokenIndex141
				}
				add(ruleQuotedText, position139)
			}
			return true
		},
		/* 12 LabelContainingDirective <- <(LabelContainingDirectiveName WS SymbolArgs)> */
		func() bool {
			position145, tokenIndex145 := position, tokenIndex
			{
				position146 := position
				if !_rules[ruleLabelContainingDirectiveName]() {
					goto l145
				}
				if !_rules[ruleWS]() {
					goto l145
				}
				if !_rules[ruleSymbolArgs]() {
					goto l145
				}
				add(ruleLabelContainingDirective, position146)
			}
			return true
		l145:
			position, tokenIndex = position145, tokenIndex145
			return false
		},
		/* 13 LabelContainingDirectiveName <- <(('.' ('x' / 'X') ('w' / 'W') ('o' / 'O') ('r' / 'R') ('d' / 'D')) / ('.' ('w' / 'W') ('o' / 'O') ('r' / 'R') ('d' / 'D')) / ('.' ('l' / 'L') ('o' / 'O') ('n' / 'N') ('g' / 'G')) / ('.' ('s' / 'S') ('e' / 'E') ('t' / 'T')) / ('.' ('b' / 'B') ('y' / 'Y') ('t' / 'T') ('e' / 'E')) / ('.' '8' ('b' / 'B') ('y' / 'Y') ('t' / 'T') ('e' / 'E')) / ('.' '4' ('b' / 'B') ('y' / 'Y') ('t' / 'T') ('e' / 'E')) / ('.' ('q' / 'Q') ('u' / 'U') ('a' / 'A') ('d' / 'D')) / ('.' ('t' / 'T') ('c' / 'C')) / ('.' ('l' / 'L') ('o' / 'O') ('c' / 'C') ('a' / 'A') ('l' / 'L') ('e' / 'E') ('n' / 'N') ('t' / 'T') ('r' / 'R') ('y' / 'Y')) / ('.' ('s' / 'S') ('i' / 'I') ('z' / 'Z') ('e' / 'E')) / ('.' ('t' / 'T') ('y' / 'Y') ('p' / 'P') ('e' / 'E')) / ('.' ('u' / 'U') ('l' / 'L') ('e' / 'E') ('b' / 'B') '1' '2' '8') / ('.' ('s' / 'S') ('l' / 'L') ('e' / 'E') ('b' / 'B') '1' '2' '8'))> */
		func() bool {
			position147, tokenIndex147 := position, tokenIndex
			{
				position148 := position
				{
					position149, tokenIndex149 := position, tokenIndex
					if buffer[position] != rune('.') {
						goto l150
					}
					position++
					{
						position151, tokenIndex151 := position, tokenIndex
						if buffer[position] != rune('x') {
							goto l152
						}
						position++
						goto l151
					l152:
						position, tokenIndex = position151, tokenIndex151
						if buffer[position] != rune('X') {
							goto l150
						}
						position++
					}
				l151:
					{
						position153, tokenIndex153 := position, tokenIndex
						if buffer[position] != rune('w') {
							goto l154
						}
						position++
						goto l153
					l154:
						position, tokenIndex = position153, tokenIndex153
						if buffer[position] != rune('W') {
							goto l150
						}
						position++
					}
				l153:
					{
						position155, tokenIndex155 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l156
						}
						position++
						goto l155
					l156:
						position, tokenIndex = position155, tokenIndex155
						if buffer[position] != rune('O') {
							goto l150
						}
						position++
					}
				l155:
					{
						position157, tokenIndex157 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l158
						}
						position++
						goto l157
					l158:
						position, tokenIndex = position157, tokenIndex157
						if buffer[position] != rune('R') {
							goto l150
						}
						position++
					}
				l157:
					{
						position159, tokenIndex159 := position, tokenIndex
						if buffer[position] != rune('d') {
							goto l160
						}
						position++
						goto l159
					l160:
						position, tokenIndex = position159, tokenIndex159
						if buffer[position] != rune('D') {
							goto l150
						}
						position++
					}
				l159:
					goto l149
				l150:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l161
					}
					position++
					{
						position162, tokenIndex162 := position, tokenIndex
						if buffer[position] != rune('w') {
							goto l163
						}
						position++
						goto l162
					l163:
						position, tokenIndex = position162, tokenIndex162
						if buffer[position] != rune('W') {
							goto l161
						}
						position++
					}
				l162:
					{
						position164, tokenIndex164 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l165
						}
						position++
						goto l164
					l165:
						position, tokenIndex = position164, tokenIndex164
						if buffer[position] != rune('O') {
							goto l161
						}
						position++
					}
				l164:
					{
						position166, tokenIndex166 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l167
						}
						position++
						goto l166
					l167:
						position, tokenIndex = position166, tokenIndex166
						if buffer[position] != rune('R') {
							goto l161
						}
						position++
					}
				l166:
					{
						position168, tokenIndex168 := position, tokenIndex
						if buffer[position] != rune('d') {
							goto l169
						}
						position++
						goto l168
					l169:
						position, tokenIndex = position168, tokenIndex168
						if buffer[position] != rune('D') {
							goto l161
						}
						position++
					}
				l168:
					goto l149
				l161:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l170
					}
					position++
					{
						position171, tokenIndex171 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l172
						}
						position++
						goto l171
					l172:
						position, tokenIndex = position171, tokenIndex171
						if buffer[position] != rune('L') {
							goto l170
						}
						position++
					}
				l171:
					{
						position173, tokenIndex173 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l174
						}
						position++
						goto l173
					l174:
						position, tokenIndex = position173, tokenIndex173
						if buffer[position] != rune('O') {
							goto l170
						}
						position++
					}
				l173:
					{
						position175, tokenIndex175 := position, tokenIndex
						if buffer[position] != rune('n') {
							goto l176
						}
						position++
						goto l175
					l176:
						position, tokenIndex = position175, tokenIndex175
						if buffer[position] != rune('N') {
							goto l170
						}
						position++
					}
				l175:
					{
						position177, tokenIndex177 := position, tokenIndex
						if buffer[position] != rune('g') {
							goto l178
						}
						position++
						goto l177
					l178:
						position, tokenIndex = position177, tokenIndex177
						if buffer[position] != rune('G') {
							goto l170
						}
						position++
					}
				l177:
					goto l149
				l170:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l179
					}
					position++
					{
						position180, tokenIndex180 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l181
						}
						position++
						goto l180
					l181:
						position, tokenIndex = position180, tokenIndex180
						if buffer[position] != rune('S') {
							goto l179
						}
						position++
					}
				l180:
					{
						position182, tokenIndex182 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l183
						}
						position++
						goto l182
					l183:
						position, tokenIndex = position182, tokenIndex182
						if buffer[position] != rune('E') {
							goto l179
						}
						position++
					}
				l182:
					{
						position184, tokenIndex184 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l185
						}
						position++
						goto l184
					l185:
						position, tokenIndex = position184, tokenIndex184
						if buffer[position] != rune('T') {
							goto l179
						}
						position++
					}
				l184:
					goto l149
				l179:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l186
					}
					position++
					{
						position187, tokenIndex187 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l188
						}
						position++
						goto l187
					l188:
						position, tokenIndex = position187, tokenIndex187
						if buffer[position] != rune('B') {
							goto l186
						}
						position++
					}
				l187:
					{
						position189, tokenIndex189 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l190
						}
						position++
						goto l189
					l190:
						position, tokenIndex = position189, tokenIndex189
						if buffer[position] != rune('Y') {
							goto l186
						}
						position++
					}
				l189:
					{
						position191, tokenIndex191 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l192
						}
						position++
						goto l191
					l192:
						position, tokenIndex = position191, tokenIndex191
						if buffer[position] != rune('T') {
							goto l186
						}
						position++
					}
				l191:
					{
						position193, tokenIndex193 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l194
						}
						position++
						goto l193
					l194:
						position, tokenIndex = position193, tokenIndex193
						if buffer[position] != rune('E') {
							goto l186
						}
						position++
					}
				l193:
					goto l149
				l186:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l195
					}
					position++
					if buffer[position] != rune('8') {
						goto l195
					}
					position++
					{
						position196, tokenIndex196 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l197
						}
						position++
						goto l196
					l197:
						position, tokenIndex = position196, tokenIndex196
						if buffer[position] != rune('B') {
							goto l195
						}
						position++
					}
				l196:
					{
						position198, tokenIndex198 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l199
						}
						position++
						goto l198
					l199:
						position, tokenIndex = position198, tokenIndex198
						if buffer[position] != rune('Y') {
							goto l195
						}
						position++
					}
				l198:
					{
						position200, tokenIndex200 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l201
						}
						position++
						goto l200
					l201:
						position, tokenIndex = position200, tokenIndex200
						if buffer[position] != rune('T') {
							goto l195
						}
						position++
					}
				l200:
					{
						position202, tokenIndex202 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l203
						}
						position++
						goto l202
					l203:
						position, tokenIndex = position202, tokenIndex202
						if buffer[position] != rune('E') {
							goto l195
						}
						position++
					}
				l202:
					goto l149
				l195:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l204
					}
					position++
					if buffer[position] != rune('4') {
						goto l204
					}
					position++
					{
						position205, tokenIndex205 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l206
						}
						position++
						goto l205
					l206:
						position, tokenIndex = position205, tokenIndex205
						if buffer[position] != rune('B') {
							goto l204
						}
						position++
					}
				l205:
					{
						position207, tokenIndex207 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l208
						}
						position++
						goto l207
					l208:
						position, tokenIndex = position207, tokenIndex207
						if buffer[position] != rune('Y') {
							goto l204
						}
						position++
					}
				l207:
					{
						position209, tokenIndex209 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l210
						}
						position++
						goto l209
					l210:
						position, tokenIndex = position209, tokenIndex209
						if buffer[position] != rune('T') {
							goto l204
						}
						position++
					}
				l209:
					{
						position211, tokenIndex211 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l212
						}
						position++
						goto l211
					l212:
						position, tokenIndex = position211, tokenIndex211
						if buffer[position] != rune('E') {
							goto l204
						}
						position++
					}
				l211:
					goto l149
				l204:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l213
					}
					position++
					{
						position214, tokenIndex214 := position, tokenIndex
						if buffer[position] != rune('q') {
							goto l215
						}
						position++
						goto l214
					l215:
						position, tokenIndex = position214, tokenIndex214
						if buffer[position] != rune('Q') {
							goto l213
						}
						position++
					}
				l214:
					{
						position216, tokenIndex216 := position, tokenIndex
						if buffer[position] != rune('u') {
							goto l217
						}
						position++
						goto l216
					l217:
						position, tokenIndex = position216, tokenIndex216
						if buffer[position] != rune('U') {
							goto l213
						}
						position++
					}
				l216:
					{
						position218, tokenIndex218 := position, tokenIndex
						if buffer[position] != rune('a') {
							goto l219
						}
						position++
						goto l218
					l219:
						position, tokenIndex = position218, tokenIndex218
						if buffer[position] != rune('A') {
							goto l213
						}
						position++
					}
				l218:
					{
						position220, tokenIndex220 := position, tokenIndex
						if buffer[position] != rune('d') {
							goto l221
						}
						position++
						goto l220
					l221:
						position, tokenIndex = position220, tokenIndex220
						if buffer[position] != rune('D') {
							goto l213
						}
						position++
					}
				l220:
					goto l149
				l213:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l222
					}
					position++
					{
						position223, tokenIndex223 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l224
						}
						position++
						goto l223
					l224:
						position, tokenIndex = position223, tokenIndex223
						if buffer[position] != rune('T') {
							goto l222
						}
						position++
					}
				l223:
					{
						position225, tokenIndex225 := position, tokenIndex
						if buffer[position] != rune('c') {
							goto l226
						}
						position++
						goto l225
					l226:
						position, tokenIndex = position225, tokenIndex225
						if buffer[position] != rune('C') {
							goto l222
						}
						position++
					}
				l225:
					goto l149
				l222:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l227
					}
					position++
					{
						position228, tokenIndex228 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l229
						}
						position++
						goto l228
					l229:
						position, tokenIndex = position228, tokenIndex228
						if buffer[position] != rune('L') {
							goto l227
						}
						position++
					}
				l228:
					{
						position230, tokenIndex230 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l231
						}
						position++
						goto l230
					l231:
						position, tokenIndex = position230, tokenIndex230
						if buffer[position] != rune('O') {
							goto l227
						}
						position++
					}
				l230:
					{
						position232, tokenIndex232 := position, tokenIndex
						if buffer[position] != rune('c') {
							goto l233
						}
						position++
						goto l232
					l233:
						position, tokenIndex = position232, tokenIndex232
						if buffer[position] != rune('C') {
							goto l227
						}
						position++
					}
				l232:
					{
						position234, tokenIndex234 := position, tokenIndex
						if buffer[position] != rune('a') {
							goto l235
						}
						position++
						goto l234
					l235:
						position, tokenIndex = position234, tokenIndex234
						if buffer[position] != rune('A') {
							goto l227
						}
						position++
					}
				l234:
					{
						position236, tokenIndex236 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l237
						}
						position++
						goto l236
					l237:
						position, tokenIndex = position236, tokenIndex236
						if buffer[position] != rune('L') {
							goto l227
						}
						position++
					}
				l236:
					{
						position238, tokenIndex238 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l239
						}
						position++
						goto l238
					l239:
						position, tokenIndex = position238, tokenIndex238
						if buffer[position] != rune('E') {
							goto l227
						}
						position++
					}
				l238:
					{
						position240, tokenIndex240 := position, tokenIndex
						if buffer[position] != rune('n') {
							goto l241
						}
						position++
						goto l240
					l241:
						position, tokenIndex = position240, tokenIndex240
						if buffer[position] != rune('N') {
							goto l227
						}
						position++
					}
				l240:
					{
						position242, tokenIndex242 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l243
						}
						position++
						goto l242
					l243:
						position, tokenIndex = position242, tokenIndex242
						if buffer[position] != rune('T') {
							goto l227
						}
						position++
					}
				l242:
					{
						position244, tokenIndex244 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l245
						}
						position++
						goto l244
					l245:
						position, tokenIndex = position244, tokenIndex244
						if buffer[position] != rune('R') {
							goto l227
						}
						position++
					}
				l244:
					{
						position246, tokenIndex246 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l247
						}
						position++
						goto l246
					l247:
						position, tokenIndex = position246, tokenIndex246
						if buffer[position] != rune('Y') {
							goto l227
						}
						position++
					}
				l246:
					goto l149
				l227:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l248
					}
					position++
					{
						position249, tokenIndex249 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l250
						}
						position++
						goto l249
					l250:
						position, tokenIndex = position249, tokenIndex249
						if buffer[position] != rune('S') {
							goto l248
						}
						position++
					}
				l249:
					{
						position251, tokenIndex251 := position, tokenIndex
						if buffer[position] != rune('i') {
							goto l252
						}
						position++
						goto l251
					l252:
						position, tokenIndex = position251, tokenIndex251
						if buffer[position] != rune('I') {
							goto l248
						}
						position++
					}
				l251:
					{
						position253, tokenIndex253 := position, tokenIndex
						if buffer[position] != rune('z') {
							goto l254
						}
						position++
						goto l253
					l254:
						position, tokenIndex = position253, tokenIndex253
						if buffer[position] != rune('Z') {
							goto l248
						}
						position++
					}
				l253:
					{
						position255, tokenIndex255 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l256
						}
						position++
						goto l255
					l256:
						position, tokenIndex = position255, tokenIndex255
						if buffer[position] != rune('E') {
							goto l248
						}
						position++
					}
				l255:
					goto l149
				l248:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l257
					}
					position++
					{
						position258, tokenIndex258 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l259
						}
						position++
						goto l258
					l259:
						position, tokenIndex = position258, tokenIndex258
						if buffer[position] != rune('T') {
							goto l257
						}
						position++
					}
				l258:
					{
						position260, tokenIndex260 := position, tokenIndex
						if buffer[position] != rune('y') {
							goto l261
						}
						position++
						goto l260
					l261:
						position, tokenIndex = position260, tokenIndex260
						if buffer[position] != rune('Y') {
							goto l257
						}
						position++
					}
				l260:
					{
						position262, tokenIndex262 := position, tokenIndex
						if buffer[position] != rune('p') {
							goto l263
						}
						position++
						goto l262
					l263:
						position, tokenIndex = position262, tokenIndex262
						if buffer[position] != rune('P') {
							goto l257
						}
						position++
					}
				l262:
					{
						position264, tokenIndex264 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l265
						}
						position++
						goto l264
					l265:
						position, tokenIndex = position264, tokenIndex264
						if buffer[position] != rune('E') {
							goto l257
						}
						position++
					}
				l264:
					goto l149
				l257:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l266
					}
					position++
					{
						position267, tokenIndex267 := position, tokenIndex
						if buffer[position] != rune('u') {
							goto l268
						}
						position++
						goto l267
					l268:
						position, tokenIndex = position267, tokenIndex267
						if buffer[position] != rune('U') {
							goto l266
						}
						position++
					}
				l267:
					{
						position269, tokenIndex269 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l270
						}
						position++
						goto l269
					l270:
						position, tokenIndex = position269, tokenIndex269
						if buffer[position] != rune('L') {
							goto l266
						}
						position++
					}
				l269:
					{
						position271, tokenIndex271 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l272
						}
						position++
						goto l271
					l272:
						position, tokenIndex = position271, tokenIndex271
						if buffer[position] != rune('E') {
							goto l266
						}
						position++
					}
				l271:
					{
						position273, tokenIndex273 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l274
						}
						position++
						goto l273
					l274:
						position, tokenIndex = position273, tokenIndex273
						if buffer[position] != rune('B') {
							goto l266
						}
						position++
					}
				l273:
					if buffer[position] != rune('1') {
						goto l266
					}
					position++
					if buffer[position] != rune('2') {
						goto l266
					}
					position++
					if buffer[position] != rune('8') {
						goto l266
					}
					position++
					goto l149
				l266:
					position, tokenIndex = position149, tokenIndex149
					if buffer[position] != rune('.') {
						goto l147
					}
					position++
					{
						position275, tokenIndex275 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l276
						}
						position++
						goto l275
					l276:
						position, tokenIndex = position275, tokenIndex275
						if buffer[position] != rune('S') {
							goto l147
						}
						position++
					}
				l275:
					{
						position277, tokenIndex277 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l278
						}
						position++
						goto l277
					l278:
						position, tokenIndex = position277, tokenIndex277
						if buffer[position] != rune('L') {
							goto l147
						}
						position++
					}
				l277:
					{
						position279, tokenIndex279 := position, tokenIndex
						if buffer[position] != rune('e') {
							goto l280
						}
						position++
						goto l279
					l280:
						position, tokenIndex = position279, tokenIndex279
						if buffer[position] != rune('E') {
							goto l147
						}
						position++
					}
				l279:
					{
						position281, tokenIndex281 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l282
						}
						position++
						goto l281
					l282:
						position, tokenIndex = position281, tokenIndex281
						if buffer[position] != rune('B') {
							goto l147
						}
						position++
					}
				l281:
					if buffer[position] != rune('1') {
						goto l147
					}
					position++
					if buffer[position] != rune('2') {
						goto l147
					}
					position++
					if buffer[position] != rune('8') {
						goto l147
					}
					position++
				}
			l149:
				add(ruleLabelContainingDirectiveName, position148)
			}
			return true
		l147:
			position, tokenIndex = position147, tokenIndex147
			return false
		},
		/* 14 SymbolArgs <- <(SymbolArg (WS? ',' WS? SymbolArg)*)> */
		func() bool {
			position283, tokenIndex283 := position, tokenIndex
			{
				position284 := position
				if !_rules[ruleSymbolArg]() {
					goto l283
				}
			l285:
				{
					position286, tokenIndex286 := position, tokenIndex
					{
						position287, tokenIndex287 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l287
						}
						goto l288
					l287:
						position, tokenIndex = position287, tokenIndex287
					}
				l288:
					if buffer[position] != rune(',') {
						goto l286
					}
					position++
					{
						position289, tokenIndex289 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l289
						}
						goto l290
					l289:
						position, tokenIndex = position289, tokenIndex289
					}
				l290:
					if !_rules[ruleSymbolArg]() {
						goto l286
					}
					goto l285
				l286:
					position, tokenIndex = position286, tokenIndex286
				}
				add(ruleSymbolArgs, position284)
			}
			return true
		l283:
			position, tokenIndex = position283, tokenIndex283
			return false
		},
		/* 15 SymbolShift <- <((('<' '<') / ('>' '>')) WS? [0-9]+)> */
		func() bool {
			position291, tokenIndex291 := position, tokenIndex
			{
				position292 := position
				{
					position293, tokenIndex293 := position, tokenIndex
					if buffer[position] != rune('<') {
						goto l294
					}
					position++
					if buffer[position] != rune('<') {
						goto l294
					}
					position++
					goto l293
				l294:
					position, tokenIndex = position293, tokenIndex293
					if buffer[position] != rune('>') {
						goto l291
					}
					position++
					if buffer[position] != rune('>') {
						goto l291
					}
					position++
				}
			l293:
				{
					position295, tokenIndex295 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l295
					}
					goto l296
				l295:
					position, tokenIndex = position295, tokenIndex295
				}
			l296:
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l291
				}
				position++
			l297:
				{
					position298, tokenIndex298 := position, tokenIndex
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l298
					}
					position++
					goto l297
				l298:
					position, tokenIndex = position298, tokenIndex298
				}
				add(ruleSymbolShift, position292)
			}
			return true
		l291:
			position, tokenIndex = position291, tokenIndex291
			return false
		},
		/* 16 SymbolArg <- <((OpenParen WS?)? (Offset / SymbolType / ((Offset / LocalSymbol / SymbolName / Dot) (WS? Operator WS? (Offset / LocalSymbol / SymbolName))*) / (LocalSymbol TCMarker?) / (SymbolName Offset) / (SymbolName TCMarker?)) (WS? CloseParen)? (WS? SymbolShift)?)> */
		func() bool {
			position299, tokenIndex299 := position, tokenIndex
			{
				position300 := position
				{
					position301, tokenIndex301 := position, tokenIndex
					if !_rules[ruleOpenParen]() {
						goto l301
					}
					{
						position303, tokenIndex303 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l303
						}
						goto l304
					l303:
						position, tokenIndex = position303, tokenIndex303
					}
				l304:
					goto l302
				l301:
					position, tokenIndex = position301, tokenIndex301
				}
			l302:
				{
					position305, tokenIndex305 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l306
					}
					goto l305
				l306:
					position, tokenIndex = position305, tokenIndex305
					if !_rules[ruleSymbolType]() {
						goto l307
					}
					goto l305
				l307:
					position, tokenIndex = position305, tokenIndex305
					{
						position309, tokenIndex309 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l310
						}
						goto l309
					l310:
						position, tokenIndex = position309, tokenIndex309
						if !_rules[ruleLocalSymbol]() {
							goto l311
						}
						goto l309
					l311:
						position, tokenIndex = position309, tokenIndex309
						if !_rules[ruleSymbolName]() {
							goto l312
						}
						goto l309
					l312:
						position, tokenIndex = position309, tokenIndex309
						if !_rules[ruleDot]() {
							goto l308
						}
					}
				l309:
				l313:
					{
						position314, tokenIndex314 := position, tokenIndex
						{
							position315, tokenIndex315 := position, tokenIndex
							if !_rules[ruleWS]() {
								goto l315
							}
							goto l316
						l315:
							position, tokenIndex = position315, tokenIndex315
						}
					l316:
						if !_rules[ruleOperator]() {
							goto l314
						}
						{
							position317, tokenIndex317 := position, tokenIndex
							if !_rules[ruleWS]() {
								goto l317
							}
							goto l318
						l317:
							position, tokenIndex = position317, tokenIndex317
						}
					l318:
						{
							position319, tokenIndex319 := position, tokenIndex
							if !_rules[ruleOffset]() {
								goto l320
							}
							goto l319
						l320:
							position, tokenIndex = position319, tokenIndex319
							if !_rules[ruleLocalSymbol]() {
								goto l321
							}
							goto l319
						l321:
							position, tokenIndex = position319, tokenIndex319
							if !_rules[ruleSymbolName]() {
								goto l314
							}
						}
					l319:
						goto l313
					l314:
						position, tokenIndex = position314, tokenIndex314
					}
					goto l305
				l308:
					position, tokenIndex = position305, tokenIndex305
					if !_rules[ruleLocalSymbol]() {
						goto l322
					}
					{
						position323, tokenIndex323 := position, tokenIndex
						if !_rules[ruleTCMarker]() {
							goto l323
						}
						goto l324
					l323:
						position, tokenIndex = position323, tokenIndex323
					}
				l324:
					goto l305
				l322:
					position, tokenIndex = position305, tokenIndex305
					if !_rules[ruleSymbolName]() {
						goto l325
					}
					if !_rules[ruleOffset]() {
						goto l325
					}
					goto l305
				l325:
					position, tokenIndex = position305, tokenIndex305
					if !_rules[ruleSymbolName]() {
						goto l299
					}
					{
						position326, tokenIndex326 := position, tokenIndex
						if !_rules[ruleTCMarker]() {
							goto l326
						}
						goto l327
					l326:
						position, tokenIndex = position326, tokenIndex326
					}
				l327:
				}
			l305:
				{
					position328, tokenIndex328 := position, tokenIndex
					{
						position330, tokenIndex330 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l330
						}
						goto l331
					l330:
						position, tokenIndex = position330, tokenIndex330
					}
				l331:
					if !_rules[ruleCloseParen]() {
						goto l328
					}
					goto l329
				l328:
					position, tokenIndex = position328, tokenIndex328
				}
			l329:
				{
					position332, tokenIndex332 := position, tokenIndex
					{
						position334, tokenIndex334 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l334
						}
						goto l335
					l334:
						position, tokenIndex = position334, tokenIndex334
					}
				l335:
					if !_rules[ruleSymbolShift]() {
						goto l332
					}
					goto l333
				l332:
					position, tokenIndex = position332, tokenIndex332
				}
			l333:
				add(ruleSymbolArg, position300)
			}
			return true
		l299:
			position, tokenIndex = position299, tokenIndex299
			return false
		},
		/* 17 OpenParen <- <'('> */
		func() bool {
			position336, tokenIndex336 := position, tokenIndex
			{
				position337 := position
				if buffer[position] != rune('(') {
					goto l336
				}
				position++
				add(ruleOpenParen, position337)
			}
			return true
		l336:
			position, tokenIndex = position336, tokenIndex336
			return false
		},
		/* 18 CloseParen <- <')'> */
		func() bool {
			position338, tokenIndex338 := position, tokenIndex
			{
				position339 := position
				if buffer[position] != rune(')') {
					goto l338
				}
				position++
				add(ruleCloseParen, position339)
			}
			return true
		l338:
			position, tokenIndex = position338, tokenIndex338
			return false
		},
		/* 19 SymbolType <- <(('@' / '%') (('f' 'u' 'n' 'c' 't' 'i' 'o' 'n') / ('o' 'b' 'j' 'e' 'c' 't')))> */
		func() bool {
			position340, tokenIndex340 := position, tokenIndex
			{
				position341 := position
				{
					position342, tokenIndex342 := position, tokenIndex
					if buffer[position] != rune('@') {
						goto l343
					}
					position++
					goto l342
				l343:
					position, tokenIndex = position342, tokenIndex342
					if buffer[position] != rune('%') {
						goto l340
					}
					position++
				}
			l342:
				{
					position344, tokenIndex344 := position, tokenIndex
					if buffer[position] != rune('f') {
						goto l345
					}
					position++
					if buffer[position] != rune('u') {
						goto l345
					}
					position++
					if buffer[position] != rune('n') {
						goto l345
					}
					position++
					if buffer[position] != rune('c') {
						goto l345
					}
					position++
					if buffer[position] != rune('t') {
						goto l345
					}
					position++
					if buffer[position] != rune('i') {
						goto l345
					}
					position++
					if buffer[position] != rune('o') {
						goto l345
					}
					position++
					if buffer[position] != rune('n') {
						goto l345
					}
					position++
					goto l344
				l345:
					position, tokenIndex = position344, tokenIndex344
					if buffer[position] != rune('o') {
						goto l340
					}
					position++
					if buffer[position] != rune('b') {
						goto l340
					}
					position++
					if buffer[position] != rune('j') {
						goto l340
					}
					position++
					if buffer[position] != rune('e') {
						goto l340
					}
					position++
					if buffer[position] != rune('c') {
						goto l340
					}
					position++
					if buffer[position] != rune('t') {
						goto l340
					}
					position++
				}
			l344:
				add(ruleSymbolType, position341)
			}
			return true
		l340:
			position, tokenIndex = position340, tokenIndex340
			return false
		},
		/* 20 Dot <- <'.'> */
		func() bool {
			position346, tokenIndex346 := position, tokenIndex
			{
				position347 := position
				if buffer[position] != rune('.') {
					goto l346
				}
				position++
				add(ruleDot, position347)
			}
			return true
		l346:
			position, tokenIndex = position346, tokenIndex346
			return false
		},
		/* 21 TCMarker <- <('[' 'T' 'C' ']')> */
		func() bool {
			position348, tokenIndex348 := position, tokenIndex
			{
				position349 := position
				if buffer[position] != rune('[') {
					goto l348
				}
				position++
				if buffer[position] != rune('T') {
					goto l348
				}
				position++
				if buffer[position] != rune('C') {
					goto l348
				}
				position++
				if buffer[position] != rune(']') {
					goto l348
				}
				position++
				add(ruleTCMarker, position349)
			}
			return true
		l348:
			position, tokenIndex = position348, tokenIndex348
			return false
		},
		/* 22 EscapedChar <- <('\\' .)> */
		func() bool {
			position350, tokenIndex350 := position, tokenIndex
			{
				position351 := position
				if buffer[position] != rune('\\') {
					goto l350
				}
				position++
				if !matchDot() {
					goto l350
				}
				add(ruleEscapedChar, position351)
			}
			return true
		l350:
			position, tokenIndex = position350, tokenIndex350
			return false
		},
		/* 23 WS <- <(' ' / '\t')+> */
		func() bool {
			position352, tokenIndex352 := position, tokenIndex
			{
				position353 := position
				{
					position356, tokenIndex356 := position, tokenIndex
					if buffer[position] != rune(' ') {
						goto l357
					}
					position++
					goto l356
				l357:
					position, tokenIndex = position356, tokenIndex356
					if buffer[position] != rune('\t') {
						goto l352
					}
					position++
				}
			l356:
			l354:
				{
					position355, tokenIndex355 := position, tokenIndex
					{
						position358, tokenIndex358 := position, tokenIndex
						if buffer[position] != rune(' ') {
							goto l359
						}
						position++
						goto l358
					l359:
						position, tokenIndex = position358, tokenIndex358
						if buffer[position] != rune('\t') {
							goto l355
						}
						position++
					}
				l358:
					goto l354
				l355:
					position, tokenIndex = position355, tokenIndex355
				}
				add(ruleWS, position353)
			}
			return true
		l352:
			position, tokenIndex = position352, tokenIndex352
			return false
		},
		/* 24 Comment <- <((('/' '/') / '#') (!'\n' .)*)> */
		func() bool {
			position360, tokenIndex360 := position, tokenIndex
			{
				position361 := position
				{
					position362, tokenIndex362 := position, tokenIndex
					if buffer[position] != rune('/') {
						goto l363
					}
					position++
					if buffer[position] != rune('/') {
						goto l363
					}
					position++
					goto l362
				l363:
					position, tokenIndex = position362, tokenIndex362
					if buffer[position] != rune('#') {
						goto l360
					}
					position++
				}
			l362:
			l364:
				{
					position365, tokenIndex365 := position, tokenIndex
					{
						position366, tokenIndex366 := position, tokenIndex
						if buffer[position] != rune('\n') {
							goto l366
						}
						position++
						goto l365
					l366:
						position, tokenIndex = position366, tokenIndex366
					}
					if !matchDot() {
						goto l365
					}
					goto l364
				l365:
					position, tokenIndex = position365, tokenIndex365
				}
				add(ruleComment, position361)
			}
			return true
		l360:
			position, tokenIndex = position360, tokenIndex360
			return false
		},
		/* 25 Label <- <((LocalSymbol / LocalLabel / SymbolName) ':')> */
		func() bool {
			position367, tokenIndex367 := position, tokenIndex
			{
				position368 := position
				{
					position369, tokenIndex369 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l370
					}
					goto l369
				l370:
					position, tokenIndex = position369, tokenIndex369
					if !_rules[ruleLocalLabel]() {
						goto l371
					}
					goto l369
				l371:
					position, tokenIndex = position369, tokenIndex369
					if !_rules[ruleSymbolName]() {
						goto l367
					}
				}
			l369:
				if buffer[position] != rune(':') {
					goto l367
				}
				position++
				add(ruleLabel, position368)
			}
			return true
		l367:
			position, tokenIndex = position367, tokenIndex367
			return false
		},
		/* 26 SymbolName <- <(([a-z] / [A-Z] / '.' / '_') ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]) / '$' / '_')*)> */
		func() bool {
			position372, tokenIndex372 := position, tokenIndex
			{
				position373 := position
				{
					position374, tokenIndex374 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l375
					}
					position++
					goto l374
				l375:
					position, tokenIndex = position374, tokenIndex374
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l376
					}
					position++
					goto l374
				l376:
					position, tokenIndex = position374, tokenIndex374
					if buffer[position] != rune('.') {
						goto l377
					}
					position++
					goto l374
				l377:
					position, tokenIndex = position374, tokenIndex374
					if buffer[position] != rune('_') {
						goto l372
					}
					position++
				}
			l374:
			l378:
				{
					position379, tokenIndex379 := position, tokenIndex
					{
						position380, tokenIndex380 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l381
						}
						position++
						goto l380
					l381:
						position, tokenIndex = position380, tokenIndex380
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l382
						}
						position++
						goto l380
					l382:
						position, tokenIndex = position380, tokenIndex380
						if buffer[position] != rune('.') {
							goto l383
						}
						position++
						goto l380
					l383:
						position, tokenIndex = position380, tokenIndex380
						{
							position385, tokenIndex385 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l386
							}
							position++
							goto l385
						l386:
							position, tokenIndex = position385, tokenIndex385
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l384
							}
							position++
						}
					l385:
						goto l380
					l384:
						position, tokenIndex = position380, tokenIndex380
						if buffer[position] != rune('$') {
							goto l387
						}
						position++
						goto l380
					l387:
						position, tokenIndex = position380, tokenIndex380
						if buffer[position] != rune('_') {
							goto l379
						}
						position++
					}
				l380:
					goto l378
				l379:
					position, tokenIndex = position379, tokenIndex379
				}
				add(ruleSymbolName, position373)
			}
			return true
		l372:
			position, tokenIndex = position372, tokenIndex372
			return false
		},
		/* 27 LocalSymbol <- <('.' 'L' ([a-z] / [A-Z] / ([a-z] / [A-Z]) / '.' / ([0-9] / [0-9]) / '$' / '_')+)> */
		func() bool {
			position388, tokenIndex388 := position, tokenIndex
			{
				position389 := position
				if buffer[position] != rune('.') {
					goto l388
				}
				position++
				if buffer[position] != rune('L') {
					goto l388
				}
				position++
				{
					position392, tokenIndex392 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l393
					}
					position++
					goto l392
				l393:
					position, tokenIndex = position392, tokenIndex392
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l394
					}
					position++
					goto l392
				l394:
					position, tokenIndex = position392, tokenIndex392
					{
						position396, tokenIndex396 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l397
						}
						position++
						goto l396
					l397:
						position, tokenIndex = position396, tokenIndex396
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l395
						}
						position++
					}
				l396:
					goto l392
				l395:
					position, tokenIndex = position392, tokenIndex392
					if buffer[position] != rune('.') {
						goto l398
					}
					position++
					goto l392
				l398:
					position, tokenIndex = position392, tokenIndex392
					{
						position400, tokenIndex400 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l401
						}
						position++
						goto l400
					l401:
						position, tokenIndex = position400, tokenIndex400
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l399
						}
						position++
					}
				l400:
					goto l392
				l399:
					position, tokenIndex = position392, tokenIndex392
					if buffer[position] != rune('$') {
						goto l402
					}
					position++
					goto l392
				l402:
					position, tokenIndex = position392, tokenIndex392
					if buffer[position] != rune('_') {
						goto l388
					}
					position++
				}
			l392:
			l390:
				{
					position391, tokenIndex391 := position, tokenIndex
					{
						position403, tokenIndex403 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l404
						}
						position++
						goto l403
					l404:
						position, tokenIndex = position403, tokenIndex403
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l405
						}
						position++
						goto l403
					l405:
						position, tokenIndex = position403, tokenIndex403
						{
							position407, tokenIndex407 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l408
							}
							position++
							goto l407
						l408:
							position, tokenIndex = position407, tokenIndex407
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l406
							}
							position++
						}
					l407:
						goto l403
					l406:
						position, tokenIndex = position403, tokenIndex403
						if buffer[position] != rune('.') {
							goto l409
						}
						position++
						goto l403
					l409:
						position, tokenIndex = position403, tokenIndex403
						{
							position411, tokenIndex411 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l412
							}
							position++
							goto l411
						l412:
							position, tokenIndex = position411, tokenIndex411
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l410
							}
							position++
						}
					l411:
						goto l403
					l410:
						position, tokenIndex = position403, tokenIndex403
						if buffer[position] != rune('$') {
							goto l413
						}
						position++
						goto l403
					l413:
						position, tokenIndex = position403, tokenIndex403
						if buffer[position] != rune('_') {
							goto l391
						}
						position++
					}
				l403:
					goto l390
				l391:
					position, tokenIndex = position391, tokenIndex391
				}
				add(ruleLocalSymbol, position389)
			}
			return true
		l388:
			position, tokenIndex = position388, tokenIndex388
			return false
		},
		/* 28 LocalLabel <- <([0-9] ([0-9] / '$')*)> */
		func() bool {
			position414, tokenIndex414 := position, tokenIndex
			{
				position415 := position
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l414
				}
				position++
			l416:
				{
					position417, tokenIndex417 := position, tokenIndex
					{
						position418, tokenIndex418 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l419
						}
						position++
						goto l418
					l419:
						position, tokenIndex = position418, tokenIndex418
						if buffer[position] != rune('$') {
							goto l417
						}
						position++
					}
				l418:
					goto l416
				l417:
					position, tokenIndex = position417, tokenIndex417
				}
				add(ruleLocalLabel, position415)
			}
			return true
		l414:
			position, tokenIndex = position414, tokenIndex414
			return false
		},
		/* 29 LocalLabelRef <- <([0-9] ([0-9] / '$')* ('b' / 'f'))> */
		func() bool {
			position420, tokenIndex420 := position, tokenIndex
			{
				position421 := position
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l420
				}
				position++
			l422:
				{
					position423, tokenIndex423 := position, tokenIndex
					{
						position424, tokenIndex424 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l425
						}
						position++
						goto l424
					l425:
						position, tokenIndex = position424, tokenIndex424
						if buffer[position] != rune('$') {
							goto l423
						}
						position++
					}
				l424:
					goto l422
				l423:
					position, tokenIndex = position423, tokenIndex423
				}
				{
					position426, tokenIndex426 := position, tokenIndex
					if buffer[position] != rune('b') {
						goto l427
					}
					position++
					goto l426
				l427:
					position, tokenIndex = position426, tokenIndex426
					if buffer[position] != rune('f') {
						goto l420
					}
					position++
				}
			l426:
				add(ruleLocalLabelRef, position421)
			}
			return true
		l420:
			position, tokenIndex = position420, tokenIndex420
			return false
		},
		/* 30 Instruction <- <(InstructionName (WS InstructionArg (WS? ',' WS? InstructionArg)*)?)> */
		func() bool {
			position428, tokenIndex428 := position, tokenIndex
			{
				position429 := position
				if !_rules[ruleInstructionName]() {
					goto l428
				}
				{
					position430, tokenIndex430 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l430
					}
					if !_rules[ruleInstructionArg]() {
						goto l430
					}
				l432:
					{
						position433, tokenIndex433 := position, tokenIndex
						{
							position434, tokenIndex434 := position, tokenIndex
							if !_rules[ruleWS]() {
								goto l434
							}
							goto l435
						l434:
							position, tokenIndex = position434, tokenIndex434
						}
					l435:
						if buffer[position] != rune(',') {
							goto l433
						}
						position++
						{
							position436, tokenIndex436 := position, tokenIndex
							if !_rules[ruleWS]() {
								goto l436
							}
							goto l437
						l436:
							position, tokenIndex = position436, tokenIndex436
						}
					l437:
						if !_rules[ruleInstructionArg]() {
							goto l433
						}
						goto l432
					l433:
						position, tokenIndex = position433, tokenIndex433
					}
					goto l431
				l430:
					position, tokenIndex = position430, tokenIndex430
				}
			l431:
				add(ruleInstruction, position429)
			}
			return true
		l428:
			position, tokenIndex = position428, tokenIndex428
			return false
		},
		/* 31 InstructionName <- <(([a-z] / [A-Z]) ([a-z] / [A-Z] / '.' / ([0-9] / [0-9]))* ('.' / '+' / '-')?)> */
		func() bool {
			position438, tokenIndex438 := position, tokenIndex
			{
				position439 := position
				{
					position440, tokenIndex440 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l441
					}
					position++
					goto l440
				l441:
					position, tokenIndex = position440, tokenIndex440
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l438
					}
					position++
				}
			l440:
			l442:
				{
					position443, tokenIndex443 := position, tokenIndex
					{
						position444, tokenIndex444 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l445
						}
						position++
						goto l444
					l445:
						position, tokenIndex = position444, tokenIndex444
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l446
						}
						position++
						goto l444
					l446:
						position, tokenIndex = position444, tokenIndex444
						if buffer[position] != rune('.') {
							goto l447
						}
						position++
						goto l444
					l447:
						position, tokenIndex = position444, tokenIndex444
						{
							position448, tokenIndex448 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l449
							}
							position++
							goto l448
						l449:
							position, tokenIndex = position448, tokenIndex448
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l443
							}
							position++
						}
					l448:
					}
				l444:
					goto l442
				l443:
					position, tokenIndex = position443, tokenIndex443
				}
				{
					position450, tokenIndex450 := position, tokenIndex
					{
						position452, tokenIndex452 := position, tokenIndex
						if buffer[position] != rune('.') {
							goto l453
						}
						position++
						goto l452
					l453:
						position, tokenIndex = position452, tokenIndex452
						if buffer[position] != rune('+') {
							goto l454
						}
						position++
						goto l452
					l454:
						position, tokenIndex = position452, tokenIndex452
						if buffer[position] != rune('-') {
							goto l450
						}
						position++
					}
				l452:
					goto l451
				l450:
					position, tokenIndex = position450, tokenIndex450
				}
			l451:
				add(ruleInstructionName, position439)
			}
			return true
		l438:
			position, tokenIndex = position438, tokenIndex438
			return false
		},
		/* 32 InstructionArg <- <(IndirectionIndicator? (ARMConstantTweak / RegisterOrConstant / LocalLabelRef / TOCRefHigh / TOCRefLow / GOTLocation / GOTSymbolOffset / MemoryRef) AVX512Token*)> */
		func() bool {
			position455, tokenIndex455 := position, tokenIndex
			{
				position456 := position
				{
					position457, tokenIndex457 := position, tokenIndex
					if !_rules[ruleIndirectionIndicator]() {
						goto l457
					}
					goto l458
				l457:
					position, tokenIndex = position457, tokenIndex457
				}
			l458:
				{
					position459, tokenIndex459 := position, tokenIndex
					if !_rules[ruleARMConstantTweak]() {
						goto l460
					}
					goto l459
				l460:
					position, tokenIndex = position459, tokenIndex459
					if !_rules[ruleRegisterOrConstant]() {
						goto l461
					}
					goto l459
				l461:
					position, tokenIndex = position459, tokenIndex459
					if !_rules[ruleLocalLabelRef]() {
						goto l462
					}
					goto l459
				l462:
					position, tokenIndex = position459, tokenIndex459
					if !_rules[ruleTOCRefHigh]() {
						goto l463
					}
					goto l459
				l463:
					position, tokenIndex = position459, tokenIndex459
					if !_rules[ruleTOCRefLow]() {
						goto l464
					}
					goto l459
				l464:
					position, tokenIndex = position459, tokenIndex459
					if !_rules[ruleGOTLocation]() {
						goto l465
					}
					goto l459
				l465:
					position, tokenIndex = position459, tokenIndex459
					if !_rules[ruleGOTSymbolOffset]() {
						goto l466
					}
					goto l459
				l466:
					position, tokenIndex = position459, tokenIndex459
					if !_rules[ruleMemoryRef]() {
						goto l455
					}
				}
			l459:
			l467:
				{
					position468, tokenIndex468 := position, tokenIndex
					if !_rules[ruleAVX512Token]() {
						goto l468
					}
					goto l467
				l468:
					position, tokenIndex = position468, tokenIndex468
				}
				add(ruleInstructionArg, position456)
			}
			return true
		l455:
			position, tokenIndex = position455, tokenIndex455
			return false
		},
		/* 33 GOTLocation <- <('$' '_' 'G' 'L' 'O' 'B' 'A' 'L' '_' 'O' 'F' 'F' 'S' 'E' 'T' '_' 'T' 'A' 'B' 'L' 'E' '_' '-' LocalSymbol)> */
		func() bool {
			position469, tokenIndex469 := position, tokenIndex
			{
				position470 := position
				if buffer[position] != rune('$') {
					goto l469
				}
				position++
				if buffer[position] != rune('_') {
					goto l469
				}
				position++
				if buffer[position] != rune('G') {
					goto l469
				}
				position++
				if buffer[position] != rune('L') {
					goto l469
				}
				position++
				if buffer[position] != rune('O') {
					goto l469
				}
				position++
				if buffer[position] != rune('B') {
					goto l469
				}
				position++
				if buffer[position] != rune('A') {
					goto l469
				}
				position++
				if buffer[position] != rune('L') {
					goto l469
				}
				position++
				if buffer[position] != rune('_') {
					goto l469
				}
				position++
				if buffer[position] != rune('O') {
					goto l469
				}
				position++
				if buffer[position] != rune('F') {
					goto l469
				}
				position++
				if buffer[position] != rune('F') {
					goto l469
				}
				position++
				if buffer[position] != rune('S') {
					goto l469
				}
				position++
				if buffer[position] != rune('E') {
					goto l469
				}
				position++
				if buffer[position] != rune('T') {
					goto l469
				}
				position++
				if buffer[position] != rune('_') {
					goto l469
				}
				position++
				if buffer[position] != rune('T') {
					goto l469
				}
				position++
				if buffer[position] != rune('A') {
					goto l469
				}
				position++
				if buffer[position] != rune('B') {
					goto l469
				}
				position++
				if buffer[position] != rune('L') {
					goto l469
				}
				position++
				if buffer[position] != rune('E') {
					goto l469
				}
				position++
				if buffer[position] != rune('_') {
					goto l469
				}
				position++
				if buffer[position] != rune('-') {
					goto l469
				}
				position++
				if !_rules[ruleLocalSymbol]() {
					goto l469
				}
				add(ruleGOTLocation, position470)
			}
			return true
		l469:
			position, tokenIndex = position469, tokenIndex469
			return false
		},
		/* 34 GOTSymbolOffset <- <(('$' SymbolName ('@' 'G' 'O' 'T') ('O' 'F' 'F')?) / (':' ('g' / 'G') ('o' / 'O') ('t' / 'T') ':' SymbolName))> */
		func() bool {
			position471, tokenIndex471 := position, tokenIndex
			{
				position472 := position
				{
					position473, tokenIndex473 := position, tokenIndex
					if buffer[position] != rune('$') {
						goto l474
					}
					position++
					if !_rules[ruleSymbolName]() {
						goto l474
					}
					if buffer[position] != rune('@') {
						goto l474
					}
					position++
					if buffer[position] != rune('G') {
						goto l474
					}
					position++
					if buffer[position] != rune('O') {
						goto l474
					}
					position++
					if buffer[position] != rune('T') {
						goto l474
					}
					position++
					{
						position475, tokenIndex475 := position, tokenIndex
						if buffer[position] != rune('O') {
							goto l475
						}
						position++
						if buffer[position] != rune('F') {
							goto l475
						}
						position++
						if buffer[position] != rune('F') {
							goto l475
						}
						position++
						goto l476
					l475:
						position, tokenIndex = position475, tokenIndex475
					}
				l476:
					goto l473
				l474:
					position, tokenIndex = position473, tokenIndex473
					if buffer[position] != rune(':') {
						goto l471
					}
					position++
					{
						position477, tokenIndex477 := position, tokenIndex
						if buffer[position] != rune('g') {
							goto l478
						}
						position++
						goto l477
					l478:
						position, tokenIndex = position477, tokenIndex477
						if buffer[position] != rune('G') {
							goto l471
						}
						position++
					}
				l477:
					{
						position479, tokenIndex479 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l480
						}
						position++
						goto l479
					l480:
						position, tokenIndex = position479, tokenIndex479
						if buffer[position] != rune('O') {
							goto l471
						}
						position++
					}
				l479:
					{
						position481, tokenIndex481 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l482
						}
						position++
						goto l481
					l482:
						position, tokenIndex = position481, tokenIndex481
						if buffer[position] != rune('T') {
							goto l471
						}
						position++
					}
				l481:
					if buffer[position] != rune(':') {
						goto l471
					}
					position++
					if !_rules[ruleSymbolName]() {
						goto l471
					}
				}
			l473:
				add(ruleGOTSymbolOffset, position472)
			}
			return true
		l471:
			position, tokenIndex = position471, tokenIndex471
			return false
		},
		/* 35 AVX512Token <- <(WS? '{' '%'? ([0-9] / [a-z])* '}')> */
		func() bool {
			position483, tokenIndex483 := position, tokenIndex
			{
				position484 := position
				{
					position485, tokenIndex485 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l485
					}
					goto l486
				l485:
					position, tokenIndex = position485, tokenIndex485
				}
			l486:
				if buffer[position] != rune('{') {
					goto l483
				}
				position++
				{
					position487, tokenIndex487 := position, tokenIndex
					if buffer[position] != rune('%') {
						goto l487
					}
					position++
					goto l488
				l487:
					position, tokenIndex = position487, tokenIndex487
				}
			l488:
			l489:
				{
					position490, tokenIndex490 := position, tokenIndex
					{
						position491, tokenIndex491 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l492
						}
						position++
						goto l491
					l492:
						position, tokenIndex = position491, tokenIndex491
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l490
						}
						position++
					}
				l491:
					goto l489
				l490:
					position, tokenIndex = position490, tokenIndex490
				}
				if buffer[position] != rune('}') {
					goto l483
				}
				position++
				add(ruleAVX512Token, position484)
			}
			return true
		l483:
			position, tokenIndex = position483, tokenIndex483
			return false
		},
		/* 36 TOCRefHigh <- <('.' 'T' 'O' 'C' '.' '-' (('0' 'b') / ('.' 'L' ([a-z] / [A-Z] / '_' / [0-9])+)) ('@' ('h' / 'H') ('a' / 'A')))> */
		func() bool {
			position493, tokenIndex493 := position, tokenIndex
			{
				position494 := position
				if buffer[position] != rune('.') {
					goto l493
				}
				position++
				if buffer[position] != rune('T') {
					goto l493
				}
				position++
				if buffer[position] != rune('O') {
					goto l493
				}
				position++
				if buffer[position] != rune('C') {
					goto l493
				}
				position++
				if buffer[position] != rune('.') {
					goto l493
				}
				position++
				if buffer[position] != rune('-') {
					goto l493
				}
				position++
				{
					position495, tokenIndex495 := position, tokenIndex
					if buffer[position] != rune('0') {
						goto l496
					}
					position++
					if buffer[position] != rune('b') {
						goto l496
					}
					position++
					goto l495
				l496:
					position, tokenIndex = position495, tokenIndex495
					if buffer[position] != rune('.') {
						goto l493
					}
					position++
					if buffer[position] != rune('L') {
						goto l493
					}
					position++
					{
						position499, tokenIndex499 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l500
						}
						position++
						goto l499
					l500:
						position, tokenIndex = position499, tokenIndex499
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l501
						}
						position++
						goto l499
					l501:
						position, tokenIndex = position499, tokenIndex499
						if buffer[position] != rune('_') {
							goto l502
						}
						position++
						goto l499
					l502:
						position, tokenIndex = position499, tokenIndex499
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l493
						}
						position++
					}
				l499:
				l497:
					{
						position498, tokenIndex498 := position, tokenIndex
						{
							position503, tokenIndex503 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l504
							}
							position++
							goto l503
						l504:
							position, tokenIndex = position503, tokenIndex503
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l505
							}
							position++
							goto l503
						l505:
							position, tokenIndex = position503, tokenIndex503
							if buffer[position] != rune('_') {
								goto l506
							}
							position++
							goto l503
						l506:
							position, tokenIndex = position503, tokenIndex503
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l498
							}
							position++
						}
					l503:
						goto l497
					l498:
						position, tokenIndex = position498, tokenIndex498
					}
				}
			l495:
				if buffer[position] != rune('@') {
					goto l493
				}
				position++
				{
					position507, tokenIndex507 := position, tokenIndex
					if buffer[position] != rune('h') {
						goto l508
					}
					position++
					goto l507
				l508:
					position, tokenIndex = position507, tokenIndex507
					if buffer[position] != rune('H') {
						goto l493
					}
					position++
				}
			l507:
				{
					position509, tokenIndex509 := position, tokenIndex
					if buffer[position] != rune('a') {
						goto l510
					}
					position++
					goto l509
				l510:
					position, tokenIndex = position509, tokenIndex509
					if buffer[position] != rune('A') {
						goto l493
					}
					position++
				}
			l509:
				add(ruleTOCRefHigh, position494)
			}
			return true
		l493:
			position, tokenIndex = position493, tokenIndex493
			return false
		},
		/* 37 TOCRefLow <- <('.' 'T' 'O' 'C' '.' '-' (('0' 'b') / ('.' 'L' ([a-z] / [A-Z] / '_' / [0-9])+)) ('@' ('l' / 'L')))> */
		func() bool {
			position511, tokenIndex511 := position, tokenIndex
			{
				position512 := position
				if buffer[position] != rune('.') {
					goto l511
				}
				position++
				if buffer[position] != rune('T') {
					goto l511
				}
				position++
				if buffer[position] != rune('O') {
					goto l511
				}
				position++
				if buffer[position] != rune('C') {
					goto l511
				}
				position++
				if buffer[position] != rune('.') {
					goto l511
				}
				position++
				if buffer[position] != rune('-') {
					goto l511
				}
				position++
				{
					position513, tokenIndex513 := position, tokenIndex
					if buffer[position] != rune('0') {
						goto l514
					}
					position++
					if buffer[position] != rune('b') {
						goto l514
					}
					position++
					goto l513
				l514:
					position, tokenIndex = position513, tokenIndex513
					if buffer[position] != rune('.') {
						goto l511
					}
					position++
					if buffer[position] != rune('L') {
						goto l511
					}
					position++
					{
						position517, tokenIndex517 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l518
						}
						position++
						goto l517
					l518:
						position, tokenIndex = position517, tokenIndex517
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l519
						}
						position++
						goto l517
					l519:
						position, tokenIndex = position517, tokenIndex517
						if buffer[position] != rune('_') {
							goto l520
						}
						position++
						goto l517
					l520:
						position, tokenIndex = position517, tokenIndex517
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l511
						}
						position++
					}
				l517:
				l515:
					{
						position516, tokenIndex516 := position, tokenIndex
						{
							position521, tokenIndex521 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l522
							}
							position++
							goto l521
						l522:
							position, tokenIndex = position521, tokenIndex521
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l523
							}
							position++
							goto l521
						l523:
							position, tokenIndex = position521, tokenIndex521
							if buffer[position] != rune('_') {
								goto l524
							}
							position++
							goto l521
						l524:
							position, tokenIndex = position521, tokenIndex521
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l516
							}
							position++
						}
					l521:
						goto l515
					l516:
						position, tokenIndex = position516, tokenIndex516
					}
				}
			l513:
				if buffer[position] != rune('@') {
					goto l511
				}
				position++
				{
					position525, tokenIndex525 := position, tokenIndex
					if buffer[position] != rune('l') {
						goto l526
					}
					position++
					goto l525
				l526:
					position, tokenIndex = position525, tokenIndex525
					if buffer[position] != rune('L') {
						goto l511
					}
					position++
				}
			l525:
				add(ruleTOCRefLow, position512)
			}
			return true
		l511:
			position, tokenIndex = position511, tokenIndex511
			return false
		},
		/* 38 IndirectionIndicator <- <'*'> */
		func() bool {
			position527, tokenIndex527 := position, tokenIndex
			{
				position528 := position
				if buffer[position] != rune('*') {
					goto l527
				}
				position++
				add(ruleIndirectionIndicator, position528)
			}
			return true
		l527:
			position, tokenIndex = position527, tokenIndex527
			return false
		},
		/* 39 RegisterOrConstant <- <((('%' ([a-z] / [A-Z]) ([a-z] / [A-Z] / ([0-9] / [0-9]))*) / ('$'? ((Offset Offset) / Offset)) / ('#' Offset ('*' [0-9]+ ('-' [0-9] [0-9]*)?)?) / ('#' '~'? '(' [0-9] WS? ('<' '<') WS? [0-9] ')') / ARMRegister) !('f' / 'b' / ':' / '(' / '+' / '-'))> */
		func() bool {
			position529, tokenIndex529 := position, tokenIndex
			{
				position530 := position
				{
					position531, tokenIndex531 := position, tokenIndex
					if buffer[position] != rune('%') {
						goto l532
					}
					position++
					{
						position533, tokenIndex533 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l534
						}
						position++
						goto l533
					l534:
						position, tokenIndex = position533, tokenIndex533
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l532
						}
						position++
					}
				l533:
				l535:
					{
						position536, tokenIndex536 := position, tokenIndex
						{
							position537, tokenIndex537 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('z') {
								goto l538
							}
							position++
							goto l537
						l538:
							position, tokenIndex = position537, tokenIndex537
							if c := buffer[position]; c < rune('A') || c > rune('Z') {
								goto l539
							}
							position++
							goto l537
						l539:
							position, tokenIndex = position537, tokenIndex537
							{
								position540, tokenIndex540 := position, tokenIndex
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l541
								}
								position++
								goto l540
							l541:
								position, tokenIndex = position540, tokenIndex540
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l536
								}
								position++
							}
						l540:
						}
					l537:
						goto l535
					l536:
						position, tokenIndex = position536, tokenIndex536
					}
					goto l531
				l532:
					position, tokenIndex = position531, tokenIndex531
					{
						position543, tokenIndex543 := position, tokenIndex
						if buffer[position] != rune('$') {
							goto l543
						}
						position++
						goto l544
					l543:
						position, tokenIndex = position543, tokenIndex543
					}
				l544:
					{
						position545, tokenIndex545 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l546
						}
						if !_rules[ruleOffset]() {
							goto l546
						}
						goto l545
					l546:
						position, tokenIndex = position545, tokenIndex545
						if !_rules[ruleOffset]() {
							goto l542
						}
					}
				l545:
					goto l531
				l542:
					position, tokenIndex = position531, tokenIndex531
					if buffer[position] != rune('#') {
						goto l547
					}
					position++
					if !_rules[ruleOffset]() {
						goto l547
					}
					{
						position548, tokenIndex548 := position, tokenIndex
						if buffer[position] != rune('*') {
							goto l548
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l548
						}
						position++
					l550:
						{
							position551, tokenIndex551 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l551
							}
							position++
							goto l550
						l551:
							position, tokenIndex = position551, tokenIndex551
						}
						{
							position552, tokenIndex552 := position, tokenIndex
							if buffer[position] != rune('-') {
								goto l552
							}
							position++
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l552
							}
							position++
						l554:
							{
								position555, tokenIndex555 := position, tokenIndex
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l555
								}
								position++
								goto l554
							l555:
								position, tokenIndex = position555, tokenIndex555
							}
							goto l553
						l552:
							position, tokenIndex = position552, tokenIndex552
						}
					l553:
						goto l549
					l548:
						position, tokenIndex = position548, tokenIndex548
					}
				l549:
					goto l531
				l547:
					position, tokenIndex = position531, tokenIndex531
					if buffer[position] != rune('#') {
						goto l556
					}
					position++
					{
						position557, tokenIndex557 := position, tokenIndex
						if buffer[position] != rune('~') {
							goto l557
						}
						position++
						goto l558
					l557:
						position, tokenIndex = position557, tokenIndex557
					}
				l558:
					if buffer[position] != rune('(') {
						goto l556
					}
					position++
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l556
					}
					position++
					{
						position559, tokenIndex559 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l559
						}
						goto l560
					l559:
						position, tokenIndex = position559, tokenIndex559
					}
				l560:
					if buffer[position] != rune('<') {
						goto l556
					}
					position++
					if buffer[position] != rune('<') {
						goto l556
					}
					position++
					{
						position561, tokenIndex561 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l561
						}
						goto l562
					l561:
						position, tokenIndex = position561, tokenIndex561
					}
				l562:
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l556
					}
					position++
					if buffer[position] != rune(')') {
						goto l556
					}
					position++
					goto l531
				l556:
					position, tokenIndex = position531, tokenIndex531
					if !_rules[ruleARMRegister]() {
						goto l529
					}
				}
			l531:
				{
					position563, tokenIndex563 := position, tokenIndex
					{
						position564, tokenIndex564 := position, tokenIndex
						if buffer[position] != rune('f') {
							goto l565
						}
						position++
						goto l564
					l565:
						position, tokenIndex = position564, tokenIndex564
						if buffer[position] != rune('b') {
							goto l566
						}
						position++
						goto l564
					l566:
						position, tokenIndex = position564, tokenIndex564
						if buffer[position] != rune(':') {
							goto l567
						}
						position++
						goto l564
					l567:
						position, tokenIndex = position564, tokenIndex564
						if buffer[position] != rune('(') {
							goto l568
						}
						position++
						goto l564
					l568:
						position, tokenIndex = position564, tokenIndex564
						if buffer[position] != rune('+') {
							goto l569
						}
						position++
						goto l564
					l569:
						position, tokenIndex = position564, tokenIndex564
						if buffer[position] != rune('-') {
							goto l563
						}
						position++
					}
				l564:
					goto l529
				l563:
					position, tokenIndex = position563, tokenIndex563
				}
				add(ruleRegisterOrConstant, position530)
			}
			return true
		l529:
			position, tokenIndex = position529, tokenIndex529
			return false
		},
		/* 40 ARMConstantTweak <- <(((('l' / 'L') ('s' / 'S') ('l' / 'L')) / (('s' / 'S') ('x' / 'X') ('t' / 'T') ('w' / 'W')) / (('s' / 'S') ('x' / 'X') ('t' / 'T') ('b' / 'B')) / (('u' / 'U') ('x' / 'X') ('t' / 'T') ('w' / 'W')) / (('u' / 'U') ('x' / 'X') ('t' / 'T') ('b' / 'B')) / (('l' / 'L') ('s' / 'S') ('r' / 'R')) / (('r' / 'R') ('o' / 'O') ('r' / 'R')) / (('a' / 'A') ('s' / 'S') ('r' / 'R'))) (WS '#' Offset)?)> */
		func() bool {
			position570, tokenIndex570 := position, tokenIndex
			{
				position571 := position
				{
					position572, tokenIndex572 := position, tokenIndex
					{
						position574, tokenIndex574 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l575
						}
						position++
						goto l574
					l575:
						position, tokenIndex = position574, tokenIndex574
						if buffer[position] != rune('L') {
							goto l573
						}
						position++
					}
				l574:
					{
						position576, tokenIndex576 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l577
						}
						position++
						goto l576
					l577:
						position, tokenIndex = position576, tokenIndex576
						if buffer[position] != rune('S') {
							goto l573
						}
						position++
					}
				l576:
					{
						position578, tokenIndex578 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l579
						}
						position++
						goto l578
					l579:
						position, tokenIndex = position578, tokenIndex578
						if buffer[position] != rune('L') {
							goto l573
						}
						position++
					}
				l578:
					goto l572
				l573:
					position, tokenIndex = position572, tokenIndex572
					{
						position581, tokenIndex581 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l582
						}
						position++
						goto l581
					l582:
						position, tokenIndex = position581, tokenIndex581
						if buffer[position] != rune('S') {
							goto l580
						}
						position++
					}
				l581:
					{
						position583, tokenIndex583 := position, tokenIndex
						if buffer[position] != rune('x') {
							goto l584
						}
						position++
						goto l583
					l584:
						position, tokenIndex = position583, tokenIndex583
						if buffer[position] != rune('X') {
							goto l580
						}
						position++
					}
				l583:
					{
						position585, tokenIndex585 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l586
						}
						position++
						goto l585
					l586:
						position, tokenIndex = position585, tokenIndex585
						if buffer[position] != rune('T') {
							goto l580
						}
						position++
					}
				l585:
					{
						position587, tokenIndex587 := position, tokenIndex
						if buffer[position] != rune('w') {
							goto l588
						}
						position++
						goto l587
					l588:
						position, tokenIndex = position587, tokenIndex587
						if buffer[position] != rune('W') {
							goto l580
						}
						position++
					}
				l587:
					goto l572
				l580:
					position, tokenIndex = position572, tokenIndex572
					{
						position590, tokenIndex590 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l591
						}
						position++
						goto l590
					l591:
						position, tokenIndex = position590, tokenIndex590
						if buffer[position] != rune('S') {
							goto l589
						}
						position++
					}
				l590:
					{
						position592, tokenIndex592 := position, tokenIndex
						if buffer[position] != rune('x') {
							goto l593
						}
						position++
						goto l592
					l593:
						position, tokenIndex = position592, tokenIndex592
						if buffer[position] != rune('X') {
							goto l589
						}
						position++
					}
				l592:
					{
						position594, tokenIndex594 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l595
						}
						position++
						goto l594
					l595:
						position, tokenIndex = position594, tokenIndex594
						if buffer[position] != rune('T') {
							goto l589
						}
						position++
					}
				l594:
					{
						position596, tokenIndex596 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l597
						}
						position++
						goto l596
					l597:
						position, tokenIndex = position596, tokenIndex596
						if buffer[position] != rune('B') {
							goto l589
						}
						position++
					}
				l596:
					goto l572
				l589:
					position, tokenIndex = position572, tokenIndex572
					{
						position599, tokenIndex599 := position, tokenIndex
						if buffer[position] != rune('u') {
							goto l600
						}
						position++
						goto l599
					l600:
						position, tokenIndex = position599, tokenIndex599
						if buffer[position] != rune('U') {
							goto l598
						}
						position++
					}
				l599:
					{
						position601, tokenIndex601 := position, tokenIndex
						if buffer[position] != rune('x') {
							goto l602
						}
						position++
						goto l601
					l602:
						position, tokenIndex = position601, tokenIndex601
						if buffer[position] != rune('X') {
							goto l598
						}
						position++
					}
				l601:
					{
						position603, tokenIndex603 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l604
						}
						position++
						goto l603
					l604:
						position, tokenIndex = position603, tokenIndex603
						if buffer[position] != rune('T') {
							goto l598
						}
						position++
					}
				l603:
					{
						position605, tokenIndex605 := position, tokenIndex
						if buffer[position] != rune('w') {
							goto l606
						}
						position++
						goto l605
					l606:
						position, tokenIndex = position605, tokenIndex605
						if buffer[position] != rune('W') {
							goto l598
						}
						position++
					}
				l605:
					goto l572
				l598:
					position, tokenIndex = position572, tokenIndex572
					{
						position608, tokenIndex608 := position, tokenIndex
						if buffer[position] != rune('u') {
							goto l609
						}
						position++
						goto l608
					l609:
						position, tokenIndex = position608, tokenIndex608
						if buffer[position] != rune('U') {
							goto l607
						}
						position++
					}
				l608:
					{
						position610, tokenIndex610 := position, tokenIndex
						if buffer[position] != rune('x') {
							goto l611
						}
						position++
						goto l610
					l611:
						position, tokenIndex = position610, tokenIndex610
						if buffer[position] != rune('X') {
							goto l607
						}
						position++
					}
				l610:
					{
						position612, tokenIndex612 := position, tokenIndex
						if buffer[position] != rune('t') {
							goto l613
						}
						position++
						goto l612
					l613:
						position, tokenIndex = position612, tokenIndex612
						if buffer[position] != rune('T') {
							goto l607
						}
						position++
					}
				l612:
					{
						position614, tokenIndex614 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l615
						}
						position++
						goto l614
					l615:
						position, tokenIndex = position614, tokenIndex614
						if buffer[position] != rune('B') {
							goto l607
						}
						position++
					}
				l614:
					goto l572
				l607:
					position, tokenIndex = position572, tokenIndex572
					{
						position617, tokenIndex617 := position, tokenIndex
						if buffer[position] != rune('l') {
							goto l618
						}
						position++
						goto l617
					l618:
						position, tokenIndex = position617, tokenIndex617
						if buffer[position] != rune('L') {
							goto l616
						}
						position++
					}
				l617:
					{
						position619, tokenIndex619 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l620
						}
						position++
						goto l619
					l620:
						position, tokenIndex = position619, tokenIndex619
						if buffer[position] != rune('S') {
							goto l616
						}
						position++
					}
				l619:
					{
						position621, tokenIndex621 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l622
						}
						position++
						goto l621
					l622:
						position, tokenIndex = position621, tokenIndex621
						if buffer[position] != rune('R') {
							goto l616
						}
						position++
					}
				l621:
					goto l572
				l616:
					position, tokenIndex = position572, tokenIndex572
					{
						position624, tokenIndex624 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l625
						}
						position++
						goto l624
					l625:
						position, tokenIndex = position624, tokenIndex624
						if buffer[position] != rune('R') {
							goto l623
						}
						position++
					}
				l624:
					{
						position626, tokenIndex626 := position, tokenIndex
						if buffer[position] != rune('o') {
							goto l627
						}
						position++
						goto l626
					l627:
						position, tokenIndex = position626, tokenIndex626
						if buffer[position] != rune('O') {
							goto l623
						}
						position++
					}
				l626:
					{
						position628, tokenIndex628 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l629
						}
						position++
						goto l628
					l629:
						position, tokenIndex = position628, tokenIndex628
						if buffer[position] != rune('R') {
							goto l623
						}
						position++
					}
				l628:
					goto l572
				l623:
					position, tokenIndex = position572, tokenIndex572
					{
						position630, tokenIndex630 := position, tokenIndex
						if buffer[position] != rune('a') {
							goto l631
						}
						position++
						goto l630
					l631:
						position, tokenIndex = position630, tokenIndex630
						if buffer[position] != rune('A') {
							goto l570
						}
						position++
					}
				l630:
					{
						position632, tokenIndex632 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l633
						}
						position++
						goto l632
					l633:
						position, tokenIndex = position632, tokenIndex632
						if buffer[position] != rune('S') {
							goto l570
						}
						position++
					}
				l632:
					{
						position634, tokenIndex634 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l635
						}
						position++
						goto l634
					l635:
						position, tokenIndex = position634, tokenIndex634
						if buffer[position] != rune('R') {
							goto l570
						}
						position++
					}
				l634:
				}
			l572:
				{
					position636, tokenIndex636 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l636
					}
					if buffer[position] != rune('#') {
						goto l636
					}
					position++
					if !_rules[ruleOffset]() {
						goto l636
					}
					goto l637
				l636:
					position, tokenIndex = position636, tokenIndex636
				}
			l637:
				add(ruleARMConstantTweak, position571)
			}
			return true
		l570:
			position, tokenIndex = position570, tokenIndex570
			return false
		},
		/* 41 ARMRegister <- <((('s' / 'S') ('p' / 'P')) / (('x' / 'w' / 'd' / 'q' / 's') [0-9] [0-9]?) / (('x' / 'X') ('z' / 'Z') ('r' / 'R')) / (('w' / 'W') ('z' / 'Z') ('r' / 'R')) / ARMVectorRegister / ('{' WS? ARMVectorRegister (',' WS? ARMVectorRegister)* WS? '}' ('[' [0-9] [0-9]? ']')?))> */
		func() bool {
			position638, tokenIndex638 := position, tokenIndex
			{
				position639 := position
				{
					position640, tokenIndex640 := position, tokenIndex
					{
						position642, tokenIndex642 := position, tokenIndex
						if buffer[position] != rune('s') {
							goto l643
						}
						position++
						goto l642
					l643:
						position, tokenIndex = position642, tokenIndex642
						if buffer[position] != rune('S') {
							goto l641
						}
						position++
					}
				l642:
					{
						position644, tokenIndex644 := position, tokenIndex
						if buffer[position] != rune('p') {
							goto l645
						}
						position++
						goto l644
					l645:
						position, tokenIndex = position644, tokenIndex644
						if buffer[position] != rune('P') {
							goto l641
						}
						position++
					}
				l644:
					goto l640
				l641:
					position, tokenIndex = position640, tokenIndex640
					{
						position647, tokenIndex647 := position, tokenIndex
						if buffer[position] != rune('x') {
							goto l648
						}
						position++
						goto l647
					l648:
						position, tokenIndex = position647, tokenIndex647
						if buffer[position] != rune('w') {
							goto l649
						}
						position++
						goto l647
					l649:
						position, tokenIndex = position647, tokenIndex647
						if buffer[position] != rune('d') {
							goto l650
						}
						position++
						goto l647
					l650:
						position, tokenIndex = position647, tokenIndex647
						if buffer[position] != rune('q') {
							goto l651
						}
						position++
						goto l647
					l651:
						position, tokenIndex = position647, tokenIndex647
						if buffer[position] != rune('s') {
							goto l646
						}
						position++
					}
				l647:
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l646
					}
					position++
					{
						position652, tokenIndex652 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l652
						}
						position++
						goto l653
					l652:
						position, tokenIndex = position652, tokenIndex652
					}
				l653:
					goto l640
				l646:
					position, tokenIndex = position640, tokenIndex640
					{
						position655, tokenIndex655 := position, tokenIndex
						if buffer[position] != rune('x') {
							goto l656
						}
						position++
						goto l655
					l656:
						position, tokenIndex = position655, tokenIndex655
						if buffer[position] != rune('X') {
							goto l654
						}
						position++
					}
				l655:
					{
						position657, tokenIndex657 := position, tokenIndex
						if buffer[position] != rune('z') {
							goto l658
						}
						position++
						goto l657
					l658:
						position, tokenIndex = position657, tokenIndex657
						if buffer[position] != rune('Z') {
							goto l654
						}
						position++
					}
				l657:
					{
						position659, tokenIndex659 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l660
						}
						position++
						goto l659
					l660:
						position, tokenIndex = position659, tokenIndex659
						if buffer[position] != rune('R') {
							goto l654
						}
						position++
					}
				l659:
					goto l640
				l654:
					position, tokenIndex = position640, tokenIndex640
					{
						position662, tokenIndex662 := position, tokenIndex
						if buffer[position] != rune('w') {
							goto l663
						}
						position++
						goto l662
					l663:
						position, tokenIndex = position662, tokenIndex662
						if buffer[position] != rune('W') {
							goto l661
						}
						position++
					}
				l662:
					{
						position664, tokenIndex664 := position, tokenIndex
						if buffer[position] != rune('z') {
							goto l665
						}
						position++
						goto l664
					l665:
						position, tokenIndex = position664, tokenIndex664
						if buffer[position] != rune('Z') {
							goto l661
						}
						position++
					}
				l664:
					{
						position666, tokenIndex666 := position, tokenIndex
						if buffer[position] != rune('r') {
							goto l667
						}
						position++
						goto l666
					l667:
						position, tokenIndex = position666, tokenIndex666
						if buffer[position] != rune('R') {
							goto l661
						}
						position++
					}
				l666:
					goto l640
				l661:
					position, tokenIndex = position640, tokenIndex640
					if !_rules[ruleARMVectorRegister]() {
						goto l668
					}
					goto l640
				l668:
					position, tokenIndex = position640, tokenIndex640
					if buffer[position] != rune('{') {
						goto l638
					}
					position++
					{
						position669, tokenIndex669 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l669
						}
						goto l670
					l669:
						position, tokenIndex = position669, tokenIndex669
					}
				l670:
					if !_rules[ruleARMVectorRegister]() {
						goto l638
					}
				l671:
					{
						position672, tokenIndex672 := position, tokenIndex
						if buffer[position] != rune(',') {
							goto l672
						}
						position++
						{
							position673, tokenIndex673 := position, tokenIndex
							if !_rules[ruleWS]() {
								goto l673
							}
							goto l674
						l673:
							position, tokenIndex = position673, tokenIndex673
						}
					l674:
						if !_rules[ruleARMVectorRegister]() {
							goto l672
						}
						goto l671
					l672:
						position, tokenIndex = position672, tokenIndex672
					}
					{
						position675, tokenIndex675 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l675
						}
						goto l676
					l675:
						position, tokenIndex = position675, tokenIndex675
					}
				l676:
					if buffer[position] != rune('}') {
						goto l638
					}
					position++
					{
						position677, tokenIndex677 := position, tokenIndex
						if buffer[position] != rune('[') {
							goto l677
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l677
						}
						position++
						{
							position679, tokenIndex679 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l679
							}
							position++
							goto l680
						l679:
							position, tokenIndex = position679, tokenIndex679
						}
					l680:
						if buffer[position] != rune(']') {
							goto l677
						}
						position++
						goto l678
					l677:
						position, tokenIndex = position677, tokenIndex677
					}
				l678:
				}
			l640:
				add(ruleARMRegister, position639)
			}
			return true
		l638:
			position, tokenIndex = position638, tokenIndex638
			return false
		},
		/* 42 ARMVectorRegister <- <(('v' / 'V') [0-9] [0-9]? ('.' [0-9]* ('b' / 's' / 'd' / 'h' / 'q') ('[' [0-9] [0-9]? ']')?)?)> */
		func() bool {
			position681, tokenIndex681 := position, tokenIndex
			{
				position682 := position
				{
					position683, tokenIndex683 := position, tokenIndex
					if buffer[position] != rune('v') {
						goto l684
					}
					position++
					goto l683
				l684:
					position, tokenIndex = position683, tokenIndex683
					if buffer[position] != rune('V') {
						goto l681
					}
					position++
				}
			l683:
				if c := buffer[position]; c < rune('0') || c > rune('9') {
					goto l681
				}
				position++
				{
					position685, tokenIndex685 := position, tokenIndex
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l685
					}
					position++
					goto l686
				l685:
					position, tokenIndex = position685, tokenIndex685
				}
			l686:
				{
					position687, tokenIndex687 := position, tokenIndex
					if buffer[position] != rune('.') {
						goto l687
					}
					position++
				l689:
					{
						position690, tokenIndex690 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l690
						}
						position++
						goto l689
					l690:
						position, tokenIndex = position690, tokenIndex690
					}
					{
						position691, tokenIndex691 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l692
						}
						position++
						goto l691
					l692:
						position, tokenIndex = position691, tokenIndex691
						if buffer[position] != rune('s') {
							goto l693
						}
						position++
						goto l691
					l693:
						position, tokenIndex = position691, tokenIndex691
						if buffer[position] != rune('d') {
							goto l694
						}
						position++
						goto l691
					l694:
						position, tokenIndex = position691, tokenIndex691
						if buffer[position] != rune('h') {
							goto l695
						}
						position++
						goto l691
					l695:
						position, tokenIndex = position691, tokenIndex691
						if buffer[position] != rune('q') {
							goto l687
						}
						position++
					}
				l691:
					{
						position696, tokenIndex696 := position, tokenIndex
						if buffer[position] != rune('[') {
							goto l696
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l696
						}
						position++
						{
							position698, tokenIndex698 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l698
							}
							position++
							goto l699
						l698:
							position, tokenIndex = position698, tokenIndex698
						}
					l699:
						if buffer[position] != rune(']') {
							goto l696
						}
						position++
						goto l697
					l696:
						position, tokenIndex = position696, tokenIndex696
					}
				l697:
					goto l688
				l687:
					position, tokenIndex = position687, tokenIndex687
				}
			l688:
				add(ruleARMVectorRegister, position682)
			}
			return true
		l681:
			position, tokenIndex = position681, tokenIndex681
			return false
		},
		/* 43 MemoryRef <- <((SymbolRef BaseIndexScale) / SymbolRef / Low12BitsSymbolRef / (Offset* BaseIndexScale) / (SegmentRegister Offset BaseIndexScale) / (SegmentRegister BaseIndexScale) / (SegmentRegister Offset) / ARMBaseIndexScale / BaseIndexScale)> */
		func() bool {
			position700, tokenIndex700 := position, tokenIndex
			{
				position701 := position
				{
					position702, tokenIndex702 := position, tokenIndex
					if !_rules[ruleSymbolRef]() {
						goto l703
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l703
					}
					goto l702
				l703:
					position, tokenIndex = position702, tokenIndex702
					if !_rules[ruleSymbolRef]() {
						goto l704
					}
					goto l702
				l704:
					position, tokenIndex = position702, tokenIndex702
					if !_rules[ruleLow12BitsSymbolRef]() {
						goto l705
					}
					goto l702
				l705:
					position, tokenIndex = position702, tokenIndex702
				l707:
					{
						position708, tokenIndex708 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l708
						}
						goto l707
					l708:
						position, tokenIndex = position708, tokenIndex708
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l706
					}
					goto l702
				l706:
					position, tokenIndex = position702, tokenIndex702
					if !_rules[ruleSegmentRegister]() {
						goto l709
					}
					if !_rules[ruleOffset]() {
						goto l709
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l709
					}
					goto l702
				l709:
					position, tokenIndex = position702, tokenIndex702
					if !_rules[ruleSegmentRegister]() {
						goto l710
					}
					if !_rules[ruleBaseIndexScale]() {
						goto l710
					}
					goto l702
				l710:
					position, tokenIndex = position702, tokenIndex702
					if !_rules[ruleSegmentRegister]() {
						goto l711
					}
					if !_rules[ruleOffset]() {
						goto l711
					}
					goto l702
				l711:
					position, tokenIndex = position702, tokenIndex702
					if !_rules[ruleARMBaseIndexScale]() {
						goto l712
					}
					goto l702
				l712:
					position, tokenIndex = position702, tokenIndex702
					if !_rules[ruleBaseIndexScale]() {
						goto l700
					}
				}
			l702:
				add(ruleMemoryRef, position701)
			}
			return true
		l700:
			position, tokenIndex = position700, tokenIndex700
			return false
		},
		/* 44 SymbolRef <- <((Offset* '+')? (LocalSymbol / SymbolName) Offset* ('@' Section Offset*)?)> */
		func() bool {
			position713, tokenIndex713 := position, tokenIndex
			{
				position714 := position
				{
					position715, tokenIndex715 := position, tokenIndex
				l717:
					{
						position718, tokenIndex718 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l718
						}
						goto l717
					l718:
						position, tokenIndex = position718, tokenIndex718
					}
					if buffer[position] != rune('+') {
						goto l715
					}
					position++
					goto l716
				l715:
					position, tokenIndex = position715, tokenIndex715
				}
			l716:
				{
					position719, tokenIndex719 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l720
					}
					goto l719
				l720:
					position, tokenIndex = position719, tokenIndex719
					if !_rules[ruleSymbolName]() {
						goto l713
					}
				}
			l719:
			l721:
				{
					position722, tokenIndex722 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l722
					}
					goto l721
				l722:
					position, tokenIndex = position722, tokenIndex722
				}
				{
					position723, tokenIndex723 := position, tokenIndex
					if buffer[position] != rune('@') {
						goto l723
					}
					position++
					if !_rules[ruleSection]() {
						goto l723
					}
				l725:
					{
						position726, tokenIndex726 := position, tokenIndex
						if !_rules[ruleOffset]() {
							goto l726
						}
						goto l725
					l726:
						position, tokenIndex = position726, tokenIndex726
					}
					goto l724
				l723:
					position, tokenIndex = position723, tokenIndex723
				}
			l724:
				add(ruleSymbolRef, position714)
			}
			return true
		l713:
			position, tokenIndex = position713, tokenIndex713
			return false
		},
		/* 45 Low12BitsSymbolRef <- <(':' ('l' / 'L') ('o' / 'O') '1' '2' ':' (LocalSymbol / SymbolName) Offset?)> */
		func() bool {
			position727, tokenIndex727 := position, tokenIndex
			{
				position728 := position
				if buffer[position] != rune(':') {
					goto l727
				}
				position++
				{
					position729, tokenIndex729 := position, tokenIndex
					if buffer[position] != rune('l') {
						goto l730
					}
					position++
					goto l729
				l730:
					position, tokenIndex = position729, tokenIndex729
					if buffer[position] != rune('L') {
						goto l727
					}
					position++
				}
			l729:
				{
					position731, tokenIndex731 := position, tokenIndex
					if buffer[position] != rune('o') {
						goto l732
					}
					position++
					goto l731
				l732:
					position, tokenIndex = position731, tokenIndex731
					if buffer[position] != rune('O') {
						goto l727
					}
					position++
				}
			l731:
				if buffer[position] != rune('1') {
					goto l727
				}
				position++
				if buffer[position] != rune('2') {
					goto l727
				}
				position++
				if buffer[position] != rune(':') {
					goto l727
				}
				position++
				{
					position733, tokenIndex733 := position, tokenIndex
					if !_rules[ruleLocalSymbol]() {
						goto l734
					}
					goto l733
				l734:
					position, tokenIndex = position733, tokenIndex733
					if !_rules[ruleSymbolName]() {
						goto l727
					}
				}
			l733:
				{
					position735, tokenIndex735 := position, tokenIndex
					if !_rules[ruleOffset]() {
						goto l735
					}
					goto l736
				l735:
					position, tokenIndex = position735, tokenIndex735
				}
			l736:
				add(ruleLow12BitsSymbolRef, position728)
			}
			return true
		l727:
			position, tokenIndex = position727, tokenIndex727
			return false
		},
		/* 46 ARMBaseIndexScale <- <('[' ARMRegister (',' WS? (('#' Offset ('*' [0-9]+)?) / ARMGOTLow12 / Low12BitsSymbolRef / ARMRegister) (',' WS? ARMConstantTweak)?)? ']' ARMPostincrement?)> */
		func() bool {
			position737, tokenIndex737 := position, tokenIndex
			{
				position738 := position
				if buffer[position] != rune('[') {
					goto l737
				}
				position++
				if !_rules[ruleARMRegister]() {
					goto l737
				}
				{
					position739, tokenIndex739 := position, tokenIndex
					if buffer[position] != rune(',') {
						goto l739
					}
					position++
					{
						position741, tokenIndex741 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l741
						}
						goto l742
					l741:
						position, tokenIndex = position741, tokenIndex741
					}
				l742:
					{
						position743, tokenIndex743 := position, tokenIndex
						if buffer[position] != rune('#') {
							goto l744
						}
						position++
						if !_rules[ruleOffset]() {
							goto l744
						}
						{
							position745, tokenIndex745 := position, tokenIndex
							if buffer[position] != rune('*') {
								goto l745
							}
							position++
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l745
							}
							position++
						l747:
							{
								position748, tokenIndex748 := position, tokenIndex
								if c := buffer[position]; c < rune('0') || c > rune('9') {
									goto l748
								}
								position++
								goto l747
							l748:
								position, tokenIndex = position748, tokenIndex748
							}
							goto l746
						l745:
							position, tokenIndex = position745, tokenIndex745
						}
					l746:
						goto l743
					l744:
						position, tokenIndex = position743, tokenIndex743
						if !_rules[ruleARMGOTLow12]() {
							goto l749
						}
						goto l743
					l749:
						position, tokenIndex = position743, tokenIndex743
						if !_rules[ruleLow12BitsSymbolRef]() {
							goto l750
						}
						goto l743
					l750:
						position, tokenIndex = position743, tokenIndex743
						if !_rules[ruleARMRegister]() {
							goto l739
						}
					}
				l743:
					{
						position751, tokenIndex751 := position, tokenIndex
						if buffer[position] != rune(',') {
							goto l751
						}
						position++
						{
							position753, tokenIndex753 := position, tokenIndex
							if !_rules[ruleWS]() {
								goto l753
							}
							goto l754
						l753:
							position, tokenIndex = position753, tokenIndex753
						}
					l754:
						if !_rules[ruleARMConstantTweak]() {
							goto l751
						}
						goto l752
					l751:
						position, tokenIndex = position751, tokenIndex751
					}
				l752:
					goto l740
				l739:
					position, tokenIndex = position739, tokenIndex739
				}
			l740:
				if buffer[position] != rune(']') {
					goto l737
				}
				position++
				{
					position755, tokenIndex755 := position, tokenIndex
					if !_rules[ruleARMPostincrement]() {
						goto l755
					}
					goto l756
				l755:
					position, tokenIndex = position755, tokenIndex755
				}
			l756:
				add(ruleARMBaseIndexScale, position738)
			}
			return true
		l737:
			position, tokenIndex = position737, tokenIndex737
			return false
		},
		/* 47 ARMGOTLow12 <- <(':' ('g' / 'G') ('o' / 'O') ('t' / 'T') '_' ('l' / 'L') ('o' / 'O') '1' '2' ':' SymbolName)> */
		func() bool {
			position757, tokenIndex757 := position, tokenIndex
			{
				position758 := position
				if buffer[position] != rune(':') {
					goto l757
				}
				position++
				{
					position759, tokenIndex759 := position, tokenIndex
					if buffer[position] != rune('g') {
						goto l760
					}
					position++
					goto l759
				l760:
					position, tokenIndex = position759, tokenIndex759
					if buffer[position] != rune('G') {
						goto l757
					}
					position++
				}
			l759:
				{
					position761, tokenIndex761 := position, tokenIndex
					if buffer[position] != rune('o') {
						goto l762
					}
					position++
					goto l761
				l762:
					position, tokenIndex = position761, tokenIndex761
					if buffer[position] != rune('O') {
						goto l757
					}
					position++
				}
			l761:
				{
					position763, tokenIndex763 := position, tokenIndex
					if buffer[position] != rune('t') {
						goto l764
					}
					position++
					goto l763
				l764:
					position, tokenIndex = position763, tokenIndex763
					if buffer[position] != rune('T') {
						goto l757
					}
					position++
				}
			l763:
				if buffer[position] != rune('_') {
					goto l757
				}
				position++
				{
					position765, tokenIndex765 := position, tokenIndex
					if buffer[position] != rune('l') {
						goto l766
					}
					position++
					goto l765
				l766:
					position, tokenIndex = position765, tokenIndex765
					if buffer[position] != rune('L') {
						goto l757
					}
					position++
				}
			l765:
				{
					position767, tokenIndex767 := position, tokenIndex
					if buffer[position] != rune('o') {
						goto l768
					}
					position++
					goto l767
				l768:
					position, tokenIndex = position767, tokenIndex767
					if buffer[position] != rune('O') {
						goto l757
					}
					position++
				}
			l767:
				if buffer[position] != rune('1') {
					goto l757
				}
				position++
				if buffer[position] != rune('2') {
					goto l757
				}
				position++
				if buffer[position] != rune(':') {
					goto l757
				}
				position++
				if !_rules[ruleSymbolName]() {
					goto l757
				}
				add(ruleARMGOTLow12, position758)
			}
			return true
		l757:
			position, tokenIndex = position757, tokenIndex757
			return false
		},
		/* 48 ARMPostincrement <- <'!'> */
		func() bool {
			position769, tokenIndex769 := position, tokenIndex
			{
				position770 := position
				if buffer[position] != rune('!') {
					goto l769
				}
				position++
				add(ruleARMPostincrement, position770)
			}
			return true
		l769:
			position, tokenIndex = position769, tokenIndex769
			return false
		},
		/* 49 BaseIndexScale <- <('(' RegisterOrConstant? WS? (',' WS? RegisterOrConstant WS? (',' [0-9]+)?)? ')')> */
		func() bool {
			position771, tokenIndex771 := position, tokenIndex
			{
				position772 := position
				if buffer[position] != rune('(') {
					goto l771
				}
				position++
				{
					position773, tokenIndex773 := position, tokenIndex
					if !_rules[ruleRegisterOrConstant]() {
						goto l773
					}
					goto l774
				l773:
					position, tokenIndex = position773, tokenIndex773
				}
			l774:
				{
					position775, tokenIndex775 := position, tokenIndex
					if !_rules[ruleWS]() {
						goto l775
					}
					goto l776
				l775:
					position, tokenIndex = position775, tokenIndex775
				}
			l776:
				{
					position777, tokenIndex777 := position, tokenIndex
					if buffer[position] != rune(',') {
						goto l777
					}
					position++
					{
						position779, tokenIndex779 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l779
						}
						goto l780
					l779:
						position, tokenIndex = position779, tokenIndex779
					}
				l780:
					if !_rules[ruleRegisterOrConstant]() {
						goto l777
					}
					{
						position781, tokenIndex781 := position, tokenIndex
						if !_rules[ruleWS]() {
							goto l781
						}
						goto l782
					l781:
						position, tokenIndex = position781, tokenIndex781
					}
				l782:
					{
						position783, tokenIndex783 := position, tokenIndex
						if buffer[position] != rune(',') {
							goto l783
						}
						position++
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l783
						}
						position++
					l785:
						{
							position786, tokenIndex786 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l786
							}
							position++
							goto l785
						l786:
							position, tokenIndex = position786, tokenIndex786
						}
						goto l784
					l783:
						position, tokenIndex = position783, tokenIndex783
					}
				l784:
					goto l778
				l777:
					position, tokenIndex = position777, tokenIndex777
				}
			l778:
				if buffer[position] != rune(')') {
					goto l771
				}
				position++
				add(ruleBaseIndexScale, position772)
			}
			return true
		l771:
			position, tokenIndex = position771, tokenIndex771
			return false
		},
		/* 50 Operator <- <('+' / '-')> */
		func() bool {
			position787, tokenIndex787 := position, tokenIndex
			{
				position788 := position
				{
					position789, tokenIndex789 := position, tokenIndex
					if buffer[position] != rune('+') {
						goto l790
					}
					position++
					goto l789
				l790:
					position, tokenIndex = position789, tokenIndex789
					if buffer[position] != rune('-') {
						goto l787
					}
					position++
				}
			l789:
				add(ruleOperator, position788)
			}
			return true
		l787:
			position, tokenIndex = position787, tokenIndex787
			return false
		},
		/* 51 Offset <- <('+'? '-'? (('0' ('b' / 'B') ('0' / '1')+) / ('0' ('x' / 'X') ([0-9] / [0-9] / ([a-f] / [A-F]))+) / [0-9]+))> */
		func() bool {
			position791, tokenIndex791 := position, tokenIndex
			{
				position792 := position
				{
					position793, tokenIndex793 := position, tokenIndex
					if buffer[position] != rune('+') {
						goto l793
					}
					position++
					goto l794
				l793:
					position, tokenIndex = position793, tokenIndex793
				}
			l794:
				{
					position795, tokenIndex795 := position, tokenIndex
					if buffer[position] != rune('-') {
						goto l795
					}
					position++
					goto l796
				l795:
					position, tokenIndex = position795, tokenIndex795
				}
			l796:
				{
					position797, tokenIndex797 := position, tokenIndex
					if buffer[position] != rune('0') {
						goto l798
					}
					position++
					{
						position799, tokenIndex799 := position, tokenIndex
						if buffer[position] != rune('b') {
							goto l800
						}
						position++
						goto l799
					l800:
						position, tokenIndex = position799, tokenIndex799
						if buffer[position] != rune('B') {
							goto l798
						}
						position++
					}
				l799:
					{
						position803, tokenIndex803 := position, tokenIndex
						if buffer[position] != rune('0') {
							goto l804
						}
						position++
						goto l803
					l804:
						position, tokenIndex = position803, tokenIndex803
						if buffer[position] != rune('1') {
							goto l798
						}
						position++
					}
				l803:
				l801:
					{
						position802, tokenIndex802 := position, tokenIndex
						{
							position805, tokenIndex805 := position, tokenIndex
							if buffer[position] != rune('0') {
								goto l806
							}
							position++
							goto l805
						l806:
							position, tokenIndex = position805, tokenIndex805
							if buffer[position] != rune('1') {
								goto l802
							}
							position++
						}
					l805:
						goto l801
					l802:
						position, tokenIndex = position802, tokenIndex802
					}
					goto l797
				l798:
					position, tokenIndex = position797, tokenIndex797
					if buffer[position] != rune('0') {
						goto l807
					}
					position++
					{
						position808, tokenIndex808 := position, tokenIndex
						if buffer[position] != rune('x') {
							goto l809
						}
						position++
						goto l808
					l809:
						position, tokenIndex = position808, tokenIndex808
						if buffer[position] != rune('X') {
							goto l807
						}
						position++
					}
				l808:
					{
						position812, tokenIndex812 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l813
						}
						position++
						goto l812
					l813:
						position, tokenIndex = position812, tokenIndex812
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l814
						}
						position++
						goto l812
					l814:
						position, tokenIndex = position812, tokenIndex812
						{
							position815, tokenIndex815 := position, tokenIndex
							if c := buffer[position]; c < rune('a') || c > rune('f') {
								goto l816
							}
							position++
							goto l815
						l816:
							position, tokenIndex = position815, tokenIndex815
							if c := buffer[position]; c < rune('A') || c > rune('F') {
								goto l807
							}
							position++
						}
					l815:
					}
				l812:
				l810:
					{
						position811, tokenIndex811 := position, tokenIndex
						{
							position817, tokenIndex817 := position, tokenIndex
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l818
							}
							position++
							goto l817
						l818:
							position, tokenIndex = position817, tokenIndex817
							if c := buffer[position]; c < rune('0') || c > rune('9') {
								goto l819
							}
							position++
							goto l817
						l819:
							position, tokenIndex = position817, tokenIndex817
							{
								position820, tokenIndex820 := position, tokenIndex
								if c := buffer[position]; c < rune('a') || c > rune('f') {
									goto l821
								}
								position++
								goto l820
							l821:
								position, tokenIndex = position820, tokenIndex820
								if c := buffer[position]; c < rune('A') || c > rune('F') {
									goto l811
								}
								position++
							}
						l820:
						}
					l817:
						goto l810
					l811:
						position, tokenIndex = position811, tokenIndex811
					}
					goto l797
				l807:
					position, tokenIndex = position797, tokenIndex797
					if c := buffer[position]; c < rune('0') || c > rune('9') {
						goto l791
					}
					position++
				l822:
					{
						position823, tokenIndex823 := position, tokenIndex
						if c := buffer[position]; c < rune('0') || c > rune('9') {
							goto l823
						}
						position++
						goto l822
					l823:
						position, tokenIndex = position823, tokenIndex823
					}
				}
			l797:
				add(ruleOffset, position792)
			}
			return true
		l791:
			position, tokenIndex = position791, tokenIndex791
			return false
		},
		/* 52 Section <- <([a-z] / [A-Z] / '@')+> */
		func() bool {
			position824, tokenIndex824 := position, tokenIndex
			{
				position825 := position
				{
					position828, tokenIndex828 := position, tokenIndex
					if c := buffer[position]; c < rune('a') || c > rune('z') {
						goto l829
					}
					position++
					goto l828
				l829:
					position, tokenIndex = position828, tokenIndex828
					if c := buffer[position]; c < rune('A') || c > rune('Z') {
						goto l830
					}
					position++
					goto l828
				l830:
					position, tokenIndex = position828, tokenIndex828
					if buffer[position] != rune('@') {
						goto l824
					}
					position++
				}
			l828:
			l826:
				{
					position827, tokenIndex827 := position, tokenIndex
					{
						position831, tokenIndex831 := position, tokenIndex
						if c := buffer[position]; c < rune('a') || c > rune('z') {
							goto l832
						}
						position++
						goto l831
					l832:
						position, tokenIndex = position831, tokenIndex831
						if c := buffer[position]; c < rune('A') || c > rune('Z') {
							goto l833
						}
						position++
						goto l831
					l833:
						position, tokenIndex = position831, tokenIndex831
						if buffer[position] != rune('@') {
							goto l827
						}
						position++
					}
				l831:
					goto l826
				l827:
					position, tokenIndex = position827, tokenIndex827
				}
				add(ruleSection, position825)
			}
			return true
		l824:
			position, tokenIndex = position824, tokenIndex824
			return false
		},
		/* 53 SegmentRegister <- <('%' ([c-g] / 's') ('s' ':'))> */
		func() bool {
			position834, tokenIndex834 := position, tokenIndex
			{
				position835 := position
				if buffer[position] != rune('%') {
					goto l834
				}
				position++
				{
					position836, tokenIndex836 := position, tokenIndex
					if c := buffer[position]; c < rune('c') || c > rune('g') {
						goto l837
					}
					position++
					goto l836
				l837:
					position, tokenIndex = position836, tokenIndex836
					if buffer[position] != rune('s') {
						goto l834
					}
					position++
				}
			l836:
				if buffer[position] != rune('s') {
					goto l834
				}
				position++
				if buffer[position] != rune(':') {
					goto l834
				}
				position++
				add(ruleSegmentRegister, position835)
			}
			return true
		l834:
			position, tokenIndex = position834, tokenIndex834
			return false
		},
	}
	p.rules = _rules
}
