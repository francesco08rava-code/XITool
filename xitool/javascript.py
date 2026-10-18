"""Analisi lessicale conservativa: const/alias/concat, senza eseguire JavaScript."""
import json


def analyze(body):
    import tree_sitter_javascript
    from tree_sitter import Language, Parser
    source = body.encode("utf-8")[:1048576]
    tree = Parser(Language(tree_sitter_javascript.language())).parse(source)
    if tree.root_node.has_error:
        return [{"quality": "UNRESOLVED", "reason": "PARSE_ERROR"}]
    rows, visited, limited = [], [0], [False]
    def text(node):
        return source[node.start_byte:node.end_byte].decode("utf-8") if node else ""
    def identifiers(node, depth=0):
        if depth > 32:
            return {"fetch", "axios", "XMLHttpRequest", "window", "xhr"}
        if node.type in ("identifier", "shorthand_property_identifier_pattern"):
            return {text(node)}
        return set().union(*(identifiers(child, depth+1) for child in node.named_children)) if node.named_children else set()
    def writes(node):
        names = set()
        stack = [node]
        while stack:
            item = stack.pop()
            if item.type in ("assignment_expression", "augmented_assignment_expression", "update_expression"):
                left = item.child_by_field_name("left") or item.child_by_field_name("argument")
                if left:
                    names |= identifiers(left)
            stack.extend(item.named_children)
        return names
    def value(node, env, depth=0):
        if not node or depth > 16:
            return None
        kind = node.type
        raw = text(node)
        if kind == "identifier":
            return env.get(raw)
        if kind == "string":
            if "\\" not in raw:
                return raw[1:-1]
            try:
                return json.loads(raw) if raw.startswith('"') else None
            except ValueError:
                return None
        if kind == "template_string":
            parts = []
            for child in node.named_children:
                if child.type == "string_fragment":
                    part = text(child)
                    if "\\" in part:
                        return None
                elif child.type == "template_substitution" and len(child.named_children) == 1:
                    part = value(child.named_children[0], env, depth+1)
                    if not isinstance(part, str):
                        return None
                else:
                    return None
                parts.append(part)
            return "".join(parts)
        if kind == "binary_expression" and text(node.child_by_field_name("operator")) == "+":
            a, b = value(node.child_by_field_name("left"), env, depth+1), value(node.child_by_field_name("right"), env, depth+1)
            return a+b if isinstance(a, str) and isinstance(b, str) and len(a)+len(b) <= 2048 else None
        if kind == "parenthesized_expression" and len(node.named_children) == 1:
            return value(node.named_children[0], env, depth+1)
        if kind == "member_expression":
            obj, prop = value(node.child_by_field_name("object"), env, depth+1), text(node.child_by_field_name("property"))
            if obj == ("namespace", "axios") and prop in ("get", "head", "options"):
                return ("call", prop)
            if obj == ("xhr",) and prop == "open":
                return ("call", "xhr")
            if obj == ("namespace", "window") and prop == "fetch":
                return ("call", "fetch")
        if kind == "new_expression" and value(node.child_by_field_name("constructor"), env, depth+1) == ("constructor", "xhr"):
            return ("xhr",)
        return None
    def walk(node, env, blocked, depth=0):
        visited[0] += 1
        if depth > 64 or visited[0] > 50000 or len(rows) >= 1000:
            limited[0] = True
            return
        if node.type in ("program", "statement_block"):
            local = dict(env)
            for child in node.named_children:
                if child.type in ("function_declaration", "class_declaration", "import_statement"):
                    binding = child.child_by_field_name("name")
                    names = identifiers(binding) if binding else identifiers(child) if child.type == "import_statement" else set()
                    for key in names:
                        local[key] = None
                if child.type in ("lexical_declaration", "variable_declaration"):
                    for declaration in child.named_children:
                        name = declaration.child_by_field_name("name")
                        if name:
                            for key in identifiers(name):
                                local[key] = None  # lexical shadowing, including before declaration
            invalid = blocked | writes(node)
            for key in invalid:
                local[key] = None
            for child in node.named_children:
                walk(child, local, invalid, depth+1)
            return
        if node.type in ("function_declaration", "function_expression", "arrow_function", "method_definition"):
            local = dict(env)
            params = node.child_by_field_name("parameters") or node.child_by_field_name("parameter")
            if params:
                for key in identifiers(params):
                    local[key] = None
            body_node = node.child_by_field_name("body")
            if body_node:
                walk(body_node, local, blocked | writes(body_node), depth+1)
            return
        if node.type in ("lexical_declaration", "variable_declaration"):
            const = text(node).lstrip().startswith("const ")
            for declaration in node.named_children:
                name, initializer = declaration.child_by_field_name("name"), declaration.child_by_field_name("value")
                if initializer:
                    walk(initializer, env, blocked, depth+1)
                if name and name.type == "identifier":
                    env[text(name)] = value(initializer, env) if const and text(name) not in blocked else None
            return
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            call = value(fn, env)
            possible = call and isinstance(call, tuple) and call[0] == "call"
            legacy_xhr = text(fn) == "xhr.open" and "xhr" not in env
            if args and (possible or legacy_xhr or text(fn) in ("fetch", "axios.get", "axios.head", "axios.options", "xhr.open")):
                arguments = args.named_children
                xhr = call == ("call", "xhr") or legacy_xhr
                index = 1 if xhr else 0
                resolved = value(arguments[index], env) if len(arguments) > index else None
                valid_method = not xhr or (arguments and value(arguments[0], env) in ("GET", "HEAD", "OPTIONS"))
                known_call = possible or legacy_xhr
                if known_call and valid_method and isinstance(resolved, str) and 0 < len(resolved) <= 2048 and not resolved.startswith(("data:", "javascript:", "#")):
                    rows.append({"url": resolved, "quality": "HEURISTIC" if legacy_xhr and not possible else "STATIC_JS", "reached": False})
                else:
                    rows.append({"quality": "UNRESOLVED", "reason": "DYNAMIC_OR_SHADOWED_ARGUMENT", "line": node.start_point[0]+1, "column": node.start_point[1]+1})
        for child in node.named_children:
            walk(child, dict(env), blocked, depth+1)
    env = {"fetch": ("call", "fetch"), "axios": ("namespace", "axios"), "window": ("namespace", "window"), "XMLHttpRequest": ("constructor", "xhr")}
    walk(tree.root_node, env, set())
    if limited[0]:
        rows = rows[:999] + [{"quality": "UNRESOLVED", "reason": "ANALYSIS_LIMIT"}]
    return list({json.dumps(row, sort_keys=True): row for row in rows}.values())


def targets(body):
    return sorted({row["url"] for row in analyze(body) if row.get("url")})
