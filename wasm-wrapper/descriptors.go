//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/btcsuite/btcd/descriptors"
)

// Parsed descriptors and the spending plans derived from them are long-lived Go
// objects with methods, which don't map onto the stateless call-per-operation
// bridge the rest of the library uses. Re-parsing the descriptor string on
// every call would throw away the miniscript AST that NewDescriptor caches, so
// instead we park each parsed *Descriptor (and each *Plan) in a handle registry
// and hand JS an opaque integer handle. The JS wrapper releases it (via free()
// or a FinalizationRegistry) when the object is collected.
//
// The GOOS=js WASM instance is single-threaded (syscall/js dispatches every
// call on one goroutine), so the registries need no locking.
var (
	descriptorHandles = map[int]*descriptors.Descriptor{}
	planHandles       = map[int]*descriptors.Plan{}

	// nextHandle is the id for the next registered object; handles are
	// never reused, so a stale handle can't alias a live object.
	nextHandle = 1
)

// registerDescriptor stores a parsed descriptor and returns its new handle.
func registerDescriptor(d *descriptors.Descriptor) int {
	h := nextHandle
	nextHandle++
	descriptorHandles[h] = d

	return h
}

// registerPlan stores a spending plan and returns its new handle.
func registerPlan(p *descriptors.Plan) int {
	h := nextHandle
	nextHandle++
	planHandles[h] = p

	return h
}

// lookupDescriptor resolves a handle argument to its parsed descriptor.
func lookupDescriptor(arg js.Value) (*descriptors.Descriptor, map[string]any) {
	d, ok := descriptorHandles[arg.Int()]
	if !ok {
		return nil, errResult("unknown descriptor handle")
	}

	return d, nil
}

// lookupPlan resolves a handle argument to its spending plan.
func lookupPlan(arg js.Value) (*descriptors.Plan, map[string]any) {
	p, ok := planHandles[arg.Int()]
	if !ok {
		return nil, errResult("unknown plan handle")
	}

	return p, nil
}

// descriptorNew parses a descriptor string, registers it and returns the handle
// plus the fields that are cheap, immutable and can't error once parsed, so the
// JS wrapper can cache them without another boundary crossing.
func descriptorNew(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "descriptor"); e != nil {
		return e
	}

	desc, err := descriptors.NewDescriptor(args[0].String())
	if err != nil {
		return errfResult("parse descriptor: %s", err)
	}

	// js.ValueOf only accepts []any, so copy the []string of raw keys over.
	keys := desc.Keys()
	jsKeys := make([]any, len(keys))
	for i, k := range keys {
		jsKeys[i] = k
	}

	return okResult(map[string]any{
		"handle":       registerDescriptor(desc),
		"descriptor":   desc.String(),
		"descType":     string(desc.DescType()),
		"multipathLen": desc.MultipathLen(),
		"keys":         jsKeys,
	})
}

// descriptorFree drops a descriptor handle from the registry. Freeing an
// unknown handle is a no-op, so double-frees are harmless.
func descriptorFree(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "handle"); e != nil {
		return e
	}

	delete(descriptorHandles, args[0].Int())

	return okResult(true)
}

// descriptorAddressAt derives the address at the given multipath and derivation
// index for the given network.
func descriptorAddressAt(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 4, "handle, network, multipathIndex, "+
		"derivationIndex"); e != nil {

		return e
	}
	desc, e := lookupDescriptor(args[0])
	if e != nil {
		return e
	}
	params, e := getNetwork(args[1].String())
	if e != nil {
		return e
	}

	addr, err := desc.AddressAt(
		params, uint32(args[2].Int()), uint32(args[3].Int()),
	)
	if err != nil {
		return errfResult("derive address: %s", err)
	}

	return okResult(addr)
}

// descriptorScriptCodeAt returns the script code (used for signature hashing)
// at the given multipath and derivation index.
func descriptorScriptCodeAt(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 3, "handle, multipathIndex, "+
		"derivationIndex"); e != nil {

		return e
	}
	desc, e := lookupDescriptor(args[0])
	if e != nil {
		return e
	}

	script, err := desc.ScriptCodeAt(
		uint32(args[1].Int()), uint32(args[2].Int()),
	)
	if err != nil {
		return errfResult("script code: %s", err)
	}

	return okResult(bytesToJS(script))
}

// descriptorLift converts the descriptor into its abstract semantic policy,
// returned as a JSON string since SemanticPolicy carries its own json tags and
// is a recursively nested tree.
func descriptorLift(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "handle"); e != nil {
		return e
	}
	desc, e := lookupDescriptor(args[0])
	if e != nil {
		return e
	}

	policy, err := desc.Lift()
	if err != nil {
		return errfResult("lift descriptor: %s", err)
	}

	encoded, err := json.Marshal(policy)
	if err != nil {
		return errfResult("marshal policy: %s", err)
	}

	return okResult(string(encoded))
}

// descriptorMaxWeightToSatisfy returns an upper bound on the input weight, in
// weight units, needed to satisfy the descriptor.
func descriptorMaxWeightToSatisfy(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "handle"); e != nil {
		return e
	}
	desc, e := lookupDescriptor(args[0])
	if e != nil {
		return e
	}

	weight, err := desc.MaxWeightToSatisfy()
	if err != nil {
		return errfResult("max weight to satisfy: %s", err)
	}

	// js.ValueOf has no uint64 case, so hand the weight over as a float64.
	return okResult(float64(weight))
}

// descriptorPlanAt builds a spending plan at the given multipath and derivation
// index from the provided assets, registers it, and returns its handle plus the
// eagerly-computed sizes. The Assets lookups are backed by JS callbacks and are
// only consulted during planning, not stored on the plan.
func descriptorPlanAt(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 4, "handle, multipathIndex, "+
		"derivationIndex, assets"); e != nil {

		return e
	}
	desc, e := lookupDescriptor(args[0])
	if e != nil {
		return e
	}

	plan, err := desc.PlanAt(
		uint32(args[1].Int()), uint32(args[2].Int()),
		assetsFromJS(args[3]),
	)
	if err != nil {
		return errfResult("create plan: %s", err)
	}

	return okResult(map[string]any{
		"handle":             registerPlan(plan),
		"satisfactionWeight": float64(plan.SatisfactionWeight()),
		"scriptSigSize":      float64(plan.ScriptSigSize()),
		"witnessSize":        float64(plan.WitnessSize()),
	})
}

// planSatisfy completes a registered plan from the JS-callback satisfier,
// returning the final witness stack and scriptSig.
func planSatisfy(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "handle, satisfier"); e != nil {
		return e
	}
	plan, e := lookupPlan(args[0])
	if e != nil {
		return e
	}

	result, err := plan.Satisfy(satisfierFromJS(args[1]))
	if err != nil {
		return errfResult("satisfy plan: %s", err)
	}

	// Hand the witness stack to JS as an array of Uint8Arrays.
	witness := make([]any, len(result.Witness))
	for i, w := range result.Witness {
		witness[i] = bytesToJS(w)
	}

	return okResult(map[string]any{
		"witness":   witness,
		"scriptSig": bytesToJS(result.ScriptSig),
	})
}

// planFree drops a plan handle from the registry. Freeing an unknown handle is
// a no-op, so double-frees are harmless.
func planFree(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "handle"); e != nil {
		return e
	}

	delete(planHandles, args[0].Int())

	return okResult(true)
}

// assetsFromJS builds a descriptors.Assets whose lookups delegate to the JS
// callbacks on the given object. A missing callback leaves the corresponding
// lookup nil, which the planner treats as "not available".
func assetsFromJS(obj js.Value) descriptors.Assets {
	var assets descriptors.Assets
	if obj.Type() != js.TypeObject {
		return assets
	}

	if fn, ok := jsFuncArg(obj, "lookupEcdsaSig"); ok {
		assets.LookupEcdsaSig = func(pk string) bool {
			return fn.Invoke(pk).Truthy()
		}
	}

	if fn, ok := jsFuncArg(obj, "lookupTapKeySpendSig"); ok {
		assets.LookupTapKeySpendSig = func(pk string) (uint32, bool) {
			return jsSizeResult(fn.Invoke(pk))
		}
	}

	if fn, ok := jsFuncArg(obj, "lookupTapLeafScriptSig"); ok {
		assets.LookupTapLeafScriptSig = func(pk, lh string) (uint32,
			bool) {

			return jsSizeResult(fn.Invoke(pk, lh))
		}
	}

	// The optional locktime bounds are plain numbers when present.
	if v := obj.Get("relativeLocktime"); v.Type() == js.TypeNumber {
		rl := uint32(v.Int())
		assets.RelativeLocktime = &rl
	}
	if v := obj.Get("absoluteLocktime"); v.Type() == js.TypeNumber {
		al := uint32(v.Int())
		assets.AbsoluteLocktime = &al
	}

	return assets
}

// satisfierFromJS builds a descriptors.Satisfier whose lookups delegate to the
// JS callbacks on the given object. A missing callback leaves the lookup nil.
func satisfierFromJS(obj js.Value) *descriptors.Satisfier {
	satisfier := &descriptors.Satisfier{}
	if obj.Type() != js.TypeObject {
		return satisfier
	}

	if fn, ok := jsFuncArg(obj, "lookupEcdsaSig"); ok {
		satisfier.LookupEcdsaSig = func(pk string) ([]byte, bool) {
			return jsBytesResult(fn.Invoke(pk))
		}
	}

	if fn, ok := jsFuncArg(obj, "lookupTapKeySpendSig"); ok {
		satisfier.LookupTapKeySpendSig = func() ([]byte, bool) {
			return jsBytesResult(fn.Invoke())
		}
	}

	if fn, ok := jsFuncArg(obj, "lookupTapLeafScriptSig"); ok {
		satisfier.LookupTapLeafScriptSig = func(pk, lh string) ([]byte,
			bool) {

			return jsBytesResult(fn.Invoke(pk, lh))
		}
	}

	return satisfier
}

// jsFuncArg returns the named property of obj if it is a JS function.
func jsFuncArg(obj js.Value, name string) (js.Value, bool) {
	fn := obj.Get(name)
	if fn.Type() != js.TypeFunction {
		return js.Value{}, false
	}

	return fn, true
}

// jsSizeResult interprets a JS asset-lookup return value that is either a
// numeric size (the signature is available) or a falsy value (not available).
func jsSizeResult(v js.Value) (uint32, bool) {
	if v.Type() != js.TypeNumber {
		return 0, false
	}

	return uint32(v.Int()), true
}

// jsBytesResult interprets a JS satisfier-lookup return value that is either
// byte data (a Uint8Array or hex string) or a falsy value (not available).
func jsBytesResult(v js.Value) ([]byte, bool) {
	switch v.Type() {
	case js.TypeObject, js.TypeString:
		b, e := bytesFromArg(v)
		if e != nil {
			return nil, false
		}

		return b, true

	default:
		return nil, false
	}
}
