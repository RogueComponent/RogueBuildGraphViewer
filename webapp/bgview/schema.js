/* bgview/schema.js -- schema reading + the tag-polarity table (R2, R3).
 *
 * Port of bgview/schema.py.
 *
 * R2: an attribute typed `TagListType` or `TagType` PRODUCES the tag(s) in
 * its value; any other attribute whose value happens to hold a `#Name` token
 * CONSUMES it. This module answers the polarity question only -- scanning
 * values for `#Name` belongs to the detectors, because R3 makes it
 * unavoidable: `FileSpec` parameters are invisible in the xsd (they land as
 * `BalancedStringType`, indistinguishable from any other free-text attr), so
 * the schema alone cannot mark inputs.
 *
 * Two sources, one interface:
 *
 *   * `Schema.fromString` reads a real `Engine/Build/Graph/Schema.xsd` -- the
 *     one the user picked out of their own UE tree. It is parsed with the same
 *     hardened, line-numbered loader used for BuildGraph scripts, because it
 *     crosses the same trust boundary and gets the same DOCTYPE/entity
 *     treatment.
 *
 *   * `Schema.fromFacts` reads `data/schema-facts.json`, bgview's own derived
 *     table of the three facts anything here consumes: which elements exist,
 *     which attributes produce tags, which are required. That is what the site
 *     ships, so that it does not redistribute Epic's EULA-licensed generated
 *     schema. See `bgview/data/NOTICE.md` and `tools/derive_schema.py`.
 *
 * The two are interchangeable for every caller. Only the xsd path can answer
 * `attrType`, which no detector asks.
 */
"use strict";

import { loadString } from "./loader.js";

// xs:attribute/@type and xs:extension/@base are qualified names like
// "tns:TagListType" or "xs:string"; only the local part matters.
export const PRODUCER_TYPES = new Set(["TagListType", "TagType"]);

function local(qname) {
  if (!qname) return qname ?? null;
  const i = qname.indexOf(":");
  return i < 0 ? qname : qname.slice(i + 1);
}

/** Attributes declared directly on one <xs:complexType>, plus its base name.
 *
 * Deliberately shallow: only xs:attribute children that are direct children
 * of `complexType`, or direct children of an <xs:extension> one level inside
 * complexContent/simpleContent. It must NOT descend into nested
 * xs:element/xs:complexType (the anonymous types behind inline
 * Do/Switch/Case/ForEach), or their attributes bleed into this type's set.
 *
 * Ceiling, same as the Python's: the two declaration shapes Schema.xsd
 * actually uses today. No xs:attributeGroup, no `ref=`, no unions. If a
 * future engine schema introduces those, this under-reports silently for the
 * new task types -- extend takeAttrs rather than guessing elsewhere.
 */
function collectTypeAttrs(complexType) {
  const direct = new Map();
  let base = null;

  const takeAttrs = (container) => {
    for (const child of container.children) {
      if (child.tag !== "attribute") continue;
      const aname = child.attrib.name;
      if (!aname) continue;
      direct.set(aname, {
        type: local(child.attrib.type),
        // Absent use= means optional (the XSD default), so `required` is
        // only ever true on an explicit match.
        required: child.attrib.use === "required",
      });
    }
  };

  takeAttrs(complexType);
  for (const child of complexType.children) {
    if (child.tag === "complexContent" || child.tag === "simpleContent") {
      for (const grandchild of child.children) {
        if (grandchild.tag === "extension") {
          base = local(grandchild.attrib.base) || base;
          takeAttrs(grandchild);
        }
      }
    }
  }
  return [direct, base];
}

/** Merge a named complexType's own attrs with its base type's, recursively. */
function resolveType(name, typeDirect, typeBase, memo, visiting) {
  if (memo.has(name)) return memo.get(name);
  // `visiting` also guards a cyclic base chain: a malformed schema must not
  // hang the tab.
  if (visiting.has(name) || !typeDirect.has(name)) return new Map();
  visiting.add(name);
  const merged = new Map();
  const base = typeBase.get(name);
  if (base && typeDirect.has(base)) {
    for (const [k, v] of resolveType(base, typeDirect, typeBase, memo, visiting)) merged.set(k, v);
  }
  for (const [k, v] of typeDirect.get(name)) merged.set(k, v);
  visiting.delete(name);
  memo.set(name, merged);
  return merged;
}

function buildElementAttrs(root) {
  const known = new Set();
  const elemTypeRef = new Map();
  const elemInline = new Map();
  const typeDirect = new Map();
  const typeBase = new Map();

  const walk = (node) => {
    if (node.tag === "element") {
      const name = node.attrib.name;
      if (name) {
        known.add(name);
        const typeAttr = node.attrib.type;
        if (typeAttr) {
          elemTypeRef.set(name, local(typeAttr));
        } else {
          const inline = node.children.find((c) => c.tag === "complexType");
          if (inline) elemInline.set(name, collectTypeAttrs(inline));
        }
      }
    } else if (node.tag === "complexType") {
      const tname = node.attrib.name;
      if (tname) {
        const [direct, base] = collectTypeAttrs(node);
        typeDirect.set(tname, direct);
        typeBase.set(tname, base);
      }
    }
    for (const child of node.children) walk(child);
  };
  walk(root);

  const memo = new Map();
  const elemAttrs = new Map();
  for (const name of known) {
    if (elemInline.has(name)) {
      const [direct, base] = elemInline.get(name);
      const merged = base ? new Map(resolveType(base, typeDirect, typeBase, memo, new Set())) : new Map();
      for (const [k, v] of direct) merged.set(k, v);
      elemAttrs.set(name, merged);
    } else if (elemTypeRef.has(name)) {
      elemAttrs.set(name, new Map(resolveType(elemTypeRef.get(name), typeDirect, typeBase, memo, new Set())));
    } else {
      elemAttrs.set(name, new Map());
    }
  }
  return elemAttrs;
}

/** The three facts every caller needs, whichever source they came from.
 *
 *  Internally this is NOT the xsd's attribute table: it is the element set,
 *  the tag-producing attributes and the required attributes -- the whole of
 *  what the detectors ask, and exactly what the derived fact table carries,
 *  so both sources land in the same shape.
 */
export class Schema {
  constructor(known, producers, required, attrTypes = null) {
    this._known = known;
    this._producers = producers;
    this._required = required;
    // Only the xsd path can fill this in; the derived table carries no types
    // because nothing consumes them. null means "not available".
    this._attrTypes = attrTypes;
    this.sourcePath = null;
    this.isBundled = false;
  }

  /** Parse a real Schema.xsd (the one inside a picked UE tree). */
  static fromString(text, path) {
    const elemAttrs = buildElementAttrs(loadString(text, path));
    const known = new Set(elemAttrs.keys());
    const producers = new Map();
    const required = new Map();
    const attrTypes = new Map();
    for (const [tag, attrs] of elemAttrs) {
      const prod = new Set();
      const req = new Set();
      const types = new Map();
      for (const [attr, info] of attrs) {
        if (PRODUCER_TYPES.has(info.type)) prod.add(attr);
        if (info.required) req.add(attr);
        types.set(attr, info.type);
      }
      if (prod.size) producers.set(tag, prod);
      if (req.size) required.set(tag, req);
      attrTypes.set(tag, types);
    }
    const obj = new Schema(known, producers, required, attrTypes);
    obj.sourcePath = path;
    return obj;
  }

  /** Read bgview's derived fact table (the parsed data/schema-facts.json). */
  static fromFacts(facts, path) {
    const elements = facts && facts.elements;
    if (!elements || typeof elements !== "object") {
      throw new Error(`schema fact table '${path}' has no elements; regenerate it with tools/derive_schema.py`);
    }
    const known = new Set();
    const producers = new Map();
    const required = new Map();
    for (const [tag, entry] of Object.entries(elements)) {
      known.add(tag);
      const prod = new Set(entry.produces || []);
      const req = new Set(entry.required || []);
      if (prod.size) producers.set(tag, prod);
      if (req.size) required.set(tag, req);
    }
    if (!known.size) {
      throw new Error(`schema fact table '${path}' lists no elements; regenerate it with tools/derive_schema.py`);
    }
    const obj = new Schema(known, producers, required);
    obj.sourcePath = path;
    return obj;
  }

  knownElement(tag) { return this._known.has(tag); }

  /** e.g. "TagListType". null when tag or attr is unknown to the schema.
   *  XSD-sourced schemas only -- the derived fact table carries polarity and
   *  requiredness, not types, so this is null there for EVERY attr. Nothing
   *  in the analyser calls it; isTagOutput is the real question. */
  attrType(tag, attr) {
    if (!this._attrTypes) return null;
    const t = this._attrTypes.get(tag);
    return t && t.has(attr) ? t.get(attr) : null;
  }

  /** R2: true only for attributes typed TagListType/TagType (incl. Node/@Produces). */
  isTagOutput(tag, attr) { return this._producers.get(tag)?.has(attr) ?? false; }

  /** An attr absent from the schema is reported not-required -- the same
   *  answer XSD gives for a present-but-unspecified `use`. Nothing is
   *  forcing it to be there either way. */
  isRequired(tag, attr) { return this._required.get(tag)?.has(attr) ?? false; }

  requiredAttrs(tag) { return new Set(this._required.get(tag) || []); }

  /** Element names the schema knows -- used by the cross-validation harness
   *  to compare this table against the Python's, entry for entry. */
  elementNames() { return [...this._known].sort(); }
}
