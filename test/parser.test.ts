import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type * as A from "../src/parser/ast.ts";
import { parse, parsePattern } from "../src/parser/parser.ts";

function ok(src: string): A.Program {
  const ast = parse(src);
  assert.deepEqual(ast.errors, [], `unexpected errors for:\n${src}\n${JSON.stringify(ast.errors)}`);
  return ast;
}

function expr(src: string): A.Expression {
  const stmt = ok(`x = ${src};`).body[0] as A.ExpressionStatement;
  return (stmt.expression as A.AssignmentExpression).right;
}

describe("parser", () => {
  it("parses common statements", () => {
    const ast = ok(`
      var a = 1, b, c = "s";
      if (a > 0) { b = 2; } else if a < 0 then b = 3 else b = 4
      while (a < 10) a++;
      do { a--; } until (a <= 0);
      repeat (3) { show_debug_message("hi"); }
      for (var i = 0; i < 10; i += 1) {}
      for (;;) { break; }
      switch (a) { case 1: case 2: b = 1; break; default: b = 0; }
      with (obj_enemy) { hp -= 1; }
      try { throw "x"; } catch (e) { show_debug_message(e); } finally { a = 0; }
      delete s;
      exit;
    `);
    assert.equal(ast.body.length, 12);
  });

  it("parses functions, constructors and inheritance", () => {
    const ast = ok(`
      function Vec2(_x = 0, _y = 0) constructor { x = _x; y = _y; static add = function(o) { return new Vec2(x + o.x, y + o.y); } }
      function Vec3(_x, _y, _z) : Vec2(_x, _y) constructor { z = _z; }
      var f = function(a) { return a * 2; };
    `);
    const vec3 = ast.body[1] as A.FunctionDeclaration;
    assert.equal(vec3.isConstructor, true);
    assert.equal(vec3.parent?.id.name, "Vec2");
    assert.equal(vec3.params.length, 3);
  });

  it("parses accessors", () => {
    const ast = ok(`a = list[| 0]; b = map[? "k"]; c = grid[# 1, 2]; d = arr[@ 3]; e = st[$ "key"]; f = arr[1, 2]; g = arr[0][1];`);
    const accessors = ast.body.map((s) => ((s as A.ExpressionStatement).expression as A.AssignmentExpression).right as A.IndexExpression);
    assert.deepEqual(
      accessors.map((a) => a.accessor),
      ["|", "?", "#", "@", "$", "", ""],
    );
  });

  it("distinguishes array literals from accessors", () => {
    const e = expr(`[@"C:\\path", $"t{1}", #FF0000]`) as A.ArrayExpression;
    assert.equal(e.type, "ArrayExpression");
    assert.deepEqual(
      e.elements.map((x) => x.type),
      ["StringLiteral", "TemplateString", "NumberLiteral"],
    );
  });

  it("parses literals", () => {
    assert.equal((expr("$FF") as A.NumberLiteral).value, 255);
    assert.equal((expr("0x1F") as A.NumberLiteral).value, 31);
    assert.equal((expr("0b101") as A.NumberLiteral).value, 5);
    assert.equal((expr("1_000") as A.NumberLiteral).value, 1000);
    assert.equal((expr(".5") as A.NumberLiteral).value, 0.5);
    assert.equal((expr("#0000FF") as A.NumberLiteral).value, 0xff0000); // BGR
    assert.equal((expr(`"a\\nb"`) as A.StringLiteral).value, "a\nb");
    assert.equal((expr(`@"a\\nb"`) as A.StringLiteral).value, "a\\nb");
    const t = expr(`$"HP: {hp} / {max_hp}"`) as A.TemplateString;
    assert.deepEqual(t.quasis, ["HP: ", " / ", ""]);
    assert.equal(t.expressions.length, 2);
  });

  it("treats = inside expressions as legacy comparison", () => {
    const ast = ok(`if (a = 1) b = 2;`);
    const test = (ast.body[0] as A.IfStatement).test as A.BinaryExpression;
    assert.equal(test.operator, "==");
    assert.equal(test.rawOperator, "=");
  });

  it("normalizes word operators", () => {
    const e = expr("a and b or not c xor d mod 2 div 3") as A.BinaryExpression;
    assert.equal(e.operator, "||");
  });

  it("respects precedence", () => {
    const e = expr("1 + 2 * 3") as A.BinaryExpression;
    assert.equal(e.operator, "+");
    assert.equal((e.right as A.BinaryExpression).operator, "*");
    const n = expr("a ?? b ?? c") as A.BinaryExpression;
    assert.equal(n.operator, "??");
    assert.equal((n.right as A.BinaryExpression).operator, "??");
    const t = expr("a ? b : c ? d : e") as A.ConditionalExpression;
    assert.equal(t.alternate.type, "ConditionalExpression");
  });

  it("parses macros, enums and regions", () => {
    const ast = ok(`
      #region Setup
      #macro SPEED 4
      #macro Debug:API "http://localhost"
      #macro LONG 1 + \\
        2
      enum State { Idle, Run = 5, Jump, }
      #endregion
    `);
    const macros = ast.body.filter((s): s is A.MacroDeclaration => s.type === "MacroDeclaration");
    assert.equal(macros.length, 3);
    assert.equal(macros[1].config, "Debug");
    assert.equal(macros[0].value?.type, "NumberLiteral");
    const en = ast.body.find((s): s is A.EnumDeclaration => s.type === "EnumDeclaration")!;
    assert.deepEqual(
      en.members.map((m) => m.id.name),
      ["Idle", "Run", "Jump"],
    );
  });

  it("parses begin/end blocks and struct literals", () => {
    const ast = ok(`if (a) begin b = { x: 1, "y": 2, z, }; end`);
    const block = (ast.body[0] as A.IfStatement).consequent as A.BlockStatement;
    const s = ((block.body[0] as A.ExpressionStatement).expression as A.AssignmentExpression).right as A.StructExpression;
    assert.equal(s.properties.length, 3);
  });

  it("splits legacy #define sections into functions", () => {
    const ast = ok(`#define first\nreturn argument0;\n\n#define second\nvar a = 1;\nreturn a;\n`);
    assert.deepEqual(
      ast.body.map((s) => (s as A.FunctionDeclaration).id.name),
      ["first", "second"],
    );
  });

  it("allows statements without semicolons", () => {
    const ast = ok("a = 1 b = 2\nc = a + b\nfoo()");
    assert.equal(ast.body.length, 4);
  });

  it("recovers from errors and keeps parsing", () => {
    const ast = parse(`a = ;\nb = 2;\nfunction f() { c = ) ; d = 4; }\ne = 5;`);
    assert.ok(ast.errors.length >= 2);
    const names = ast.body.flatMap((s) => (s.type === "ExpressionStatement" && s.expression.type === "AssignmentExpression" && s.expression.left.type === "Identifier" ? [s.expression.left.name] : []));
    assert.ok(names.includes("b") && names.includes("e"), `got ${names}`);
  });

  it("parses patterns with metavariables and ellipsis", () => {
    const { node, errors } = parsePattern("instance_create_layer(..., $OBJ)");
    assert.deepEqual(errors, []);
    const call = node as A.CallExpression;
    assert.equal(call.arguments[0].type, "PatternEllipsis");
    assert.equal(call.arguments[1].type, "Metavariable");
  });
});
