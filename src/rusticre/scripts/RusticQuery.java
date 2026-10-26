// Address-based, bounded queries, one per run, through Hydra Engine's `script` command.
// Queries run contained (the engine rolls back an outer transaction), so they cannot
// change what other clients see or what is saved. Only `apply_overlays`, sent on a
// working copy this client owns, keeps its changes; the canonical project is never written.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.data.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.data.DataTypeParser;
import com.google.gson.*;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.*;

public class RusticQuery extends GhidraScript {
    private final Gson json = new Gson();
    private DecompInterface decompiler;

    // Decompilers outlive one run: the engine reuses this class while its source is
    // unchanged, so a warm query skips the native decompiler's start (about 250 ms).
    // One pool per program object; a change to the program flushes a borrowed
    // decompiler's cache, and closing the program disposes its pool.
    private static final Object POOL_LOCK = new Object();
    private static final Map<Program, ArrayDeque<DecompInterface>> POOLS = new IdentityHashMap<>();
    private static final Map<DecompInterface, Long> SEEN = new IdentityHashMap<>();
    private static final int POOL_SIZE = 4;

    private static DecompInterface borrow(Program program) {
        DecompInterface found = null;
        synchronized (POOL_LOCK) {
            ArrayDeque<DecompInterface> pool = POOLS.get(program);
            if (pool == null) {
                pool = new ArrayDeque<>();
                POOLS.put(program, pool);
                program.addCloseListener(closed -> {
                    synchronized (POOL_LOCK) {
                        ArrayDeque<DecompInterface> gone = POOLS.remove(program);
                        if (gone != null) for (DecompInterface d : gone) { SEEN.remove(d); d.dispose(); }
                    }
                });
            }
            found = pool.pollFirst();
        }
        if (found == null) {
            found = new DecompInterface();
            if (!found.openProgram(program)) {
                String message = found.getLastMessage();
                found.dispose();
                throw new IllegalStateException(message);
            }
        }
        else {
            Long seen;
            synchronized (POOL_LOCK) { seen = SEEN.get(found); }
            if (seen == null || seen != program.getModificationNumber()) found.flushCache();
        }
        return found;
    }

    private static void giveBack(Program program, DecompInterface decompiler, boolean healthy) {
        synchronized (POOL_LOCK) {
            ArrayDeque<DecompInterface> pool = POOLS.get(program);
            if (healthy && pool != null && pool.size() < POOL_SIZE && !program.isClosed()) {
                SEEN.put(decompiler, program.getModificationNumber());
                pool.addFirst(decompiler);
                return;
            }
            SEEN.remove(decompiler);
        }
        decompiler.dispose();
    }

    private String clip(String value, int maximum) {
        return value == null ? "" : value.substring(0, Math.min(value.length(), maximum));
    }

    private int number(JsonObject value, String key, int fallback) {
        return value.has(key) ? value.get(key).getAsInt() : fallback;
    }

    private JsonObject options(JsonObject req) {
        return req.has("options") ? req.getAsJsonObject("options") : new JsonObject();
    }

    private int remaining(long deadline) {
        return Math.max(1, (int) TimeUnit.NANOSECONDS.toSeconds(Math.max(0, deadline - System.nanoTime())));
    }

    private DecompileResults decompile(Function function, long deadline) throws Exception {
        monitor.checkCancelled();
        if (System.nanoTime() >= deadline) throw new IllegalStateException("analysis query deadline reached");
        if (decompiler == null) decompiler = borrow(currentProgram);
        DecompileResults result = decompiler.decompileFunction(function, remaining(deadline), monitor);
        if (!result.decompileCompleted() || result.getHighFunction() == null)
            throw new IllegalStateException("decompile refused: " + result.getErrorMessage());
        return result;
    }

    private JsonObject typeSummary(DataType type) {
        JsonObject row = new JsonObject();
        row.addProperty("path", clip(type.getPathName(), 512));
        row.addProperty("name", clip(type.getDisplayName(), 512));
        row.addProperty("length", type.getLength());
        row.addProperty("alignment", type.getAlignment());
        row.addProperty("kind", type.getClass().getSimpleName());
        return row;
    }

    private DataType resolveType(String name) throws Exception {
        var manager = currentProgram.getDataTypeManager();
        DataType type = manager.getDataType(name);
        if (type == null) type = BuiltInDataTypeManager.getDataTypeManager().getDataType(name);
        if (type == null) type = new DataTypeParser(manager, manager, null, DataTypeParser.AllowedDataTypes.ALL).parse(name);
        if (type == null) throw new IllegalArgumentException("unknown type: " + name);
        return type;
    }

    private JsonObject dataSummary(ghidra.program.model.listing.Data data) {
        JsonObject row = new JsonObject();
        row.addProperty("address", "0x" + data.getAddress());
        row.addProperty("type", clip(data.getDataType().getPathName(), 512));
        row.addProperty("length", data.getLength());
        row.addProperty("field", clip(data.getFieldName(), 128));
        if (data.getLength() <= 1024) row.addProperty("value", clip(data.getDefaultValueRepresentation(), 1024));
        else row.addProperty("value", "not materialized: defined value exceeds 1024 bytes");
        return row;
    }

    private void data(JsonObject req, JsonObject out, long deadline) throws Exception {
        String cursor = text(req, "cursor");
        Address addr = address(cursor.isEmpty() ? text(req, "address") : cursor);
        out.addProperty("selected_address", "0x" + addr);
        var defined = currentProgram.getListing().getDefinedDataContaining(addr);
        JsonObject opts = options(req);
        boolean table = opts.has("table") && opts.get("table").getAsBoolean();
        if (defined == null && !table) throw new IllegalArgumentException("no defined data contains this address; table=true requests raw pointer candidates");
        int limit = req.get("limit").getAsInt();
        if (defined != null) {
            JsonObject row = dataSummary(defined);
            row.addProperty("offset_into_data", addr.subtract(defined.getAddress()));
            JsonArray fields = new JsonArray();
            int components = defined.getNumComponents();
            for (int i = 0; i < components && fields.size() < Math.min(limit, 64) && System.nanoTime() < deadline; i++) {
                var component = defined.getComponent(i);
                if (component != null) fields.add(dataSummary(component));
            }
            row.add("components", fields);
            row.addProperty("components_truncated", components > fields.size());
            out.add("data", row);
        } else out.add("data", JsonNull.INSTANCE);
        JsonArray incoming = new JsonArray(), outgoing = new JsonArray();
        var references = currentProgram.getReferenceManager().getReferencesTo(addr);
        while (references.hasNext() && incoming.size() < limit && System.nanoTime() < deadline) {
            var reference = references.next(); JsonObject row = new JsonObject();
            row.addProperty("from", "0x" + reference.getFromAddress()); row.addProperty("type", reference.getReferenceType().toString()); incoming.add(row);
        }
        var from = currentProgram.getReferenceManager().getReferencesFrom(addr);
        for (int i = 0; i < from.length && outgoing.size() < limit && System.nanoTime() < deadline; i++) {
            JsonObject row = new JsonObject(); row.addProperty("to", "0x" + from[i].getToAddress()); row.addProperty("type", from[i].getReferenceType().toString()); outgoing.add(row);
        }
        out.add("references_to", incoming); out.add("references_from", outgoing);
        out.addProperty("references_truncated", references.hasNext() || from.length > outgoing.size());
        if (table) {
            int size = currentProgram.getDefaultPointerSize();
            if (size != 4 && size != 8) throw new IllegalArgumentException("raw pointer table view supports 4- or 8-byte program pointers");
            JsonArray rows = new JsonArray();
            boolean truncated = false;
            for (int i = 0; i < limit && System.nanoTime() < deadline; i++) {
                Address slot = addr.add((long) i * size);
                var block = currentProgram.getMemory().getBlock(slot);
                if (block == null || !block.isInitialized() || !block.contains(slot.add(size - 1))) { truncated = true; break; }
                long value = size == 8 ? currentProgram.getMemory().getLong(slot) : Integer.toUnsignedLong(currentProgram.getMemory().getInt(slot));
                Address target = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
                var targetBlock = currentProgram.getMemory().getBlock(target);
                JsonObject row = new JsonObject(); row.addProperty("slot", "0x" + slot);
                row.addProperty("value", "0x" + Long.toUnsignedString(value, 16)); row.addProperty("mapped", targetBlock != null);
                row.addProperty("executable", targetBlock != null && targetBlock.isExecute());
                Function function = currentProgram.getFunctionManager().getFunctionAt(target);
                if (function != null) { row.addProperty("target_function", clip(function.getName(), 512)); row.addProperty("target_entry", "0x" + function.getEntryPoint()); }
                rows.add(row);
            }
            out.add("pointer_candidates", rows);
            out.addProperty("pointer_size", size);
            out.addProperty("table_truncated", truncated || rows.size() >= limit || System.nanoTime() >= deadline);
            if (rows.size() > 0) out.addProperty("next_cursor", "0x" + addr.add((long) rows.size() * size));
        }
        out.addProperty("provenance", "saved Ghidra data, references and initialized memory; consecutive raw words are pointer candidates, not proof of vtable extent or runtime objects");
    }

    private void scan(JsonObject req, JsonObject out, long deadline) throws Exception {
        JsonObject opts = options(req);
        String cursor = text(req, "cursor");
        Address start = address(cursor.isEmpty() ? text(req, "address") : cursor);
        Address end = text(opts, "end").isEmpty() ? null : address(text(opts, "end"));
        if (end != null && end.compareTo(start) < 0) throw new IllegalArgumentException("scan end precedes its start/cursor");
        var instructions = currentProgram.getListing().getInstructions(start, true);
        JsonArray rows = new JsonArray();
        String mnemonic = text(opts, "mnemonic").toLowerCase(Locale.ROOT);
        String operand = text(opts, "operand").toLowerCase(Locale.ROOT);
        int scanned = 0, limit = req.get("limit").getAsInt();
        Address next = null;
        boolean pastEnd = false;
        while (instructions.hasNext() && scanned < 2000 && rows.size() < limit && System.nanoTime() < deadline) {
            monitor.checkCancelled();
            var instruction = instructions.next();
            if (end != null && instruction.getAddress().compareTo(end) > 0) { pastEnd = true; break; }
            scanned++; next = instruction.getMaxAddress().next();
            String operands = "";
            for (int i = 0; i < instruction.getNumOperands(); i++) operands += (i == 0 ? "" : ", ") + instruction.getDefaultOperandRepresentation(i);
            if (!instruction.getMnemonicString().toLowerCase(Locale.ROOT).contains(mnemonic) || !operands.toLowerCase(Locale.ROOT).contains(operand)) continue;
            JsonObject row = new JsonObject(); row.addProperty("address", "0x" + instruction.getAddress());
            row.addProperty("mnemonic", instruction.getMnemonicString()); row.addProperty("operands", clip(operands, 1024));
            byte[] bytes = instruction.getBytes();
            row.addProperty("bytes", HexFormat.ofDelimiter(" ").withUpperCase().formatHex(bytes, 0, Math.min(bytes.length, 32)));
            row.addProperty("bytes_truncated", bytes.length > 32);
            row.addProperty("instruction", clip(instruction.toString(), 1024)); rows.add(row);
        }
        boolean more = !pastEnd && instructions.hasNext() && (next == null || end == null || next.compareTo(end) <= 0);
        out.add("instructions", rows); out.addProperty("scanned", scanned); out.addProperty("truncated", more);
        if (more) out.addProperty("next_cursor", "0x" + (next == null ? start : next));
        out.addProperty("provenance", "decoded instructions in saved Ghidra listing; literal filters, no new disassembly or regex evaluation");
    }

    private void types(JsonObject req, JsonObject out, long deadline) throws Exception {
        var iterator = currentProgram.getDataTypeManager().getAllDataTypes();
        String cursor = text(req, "cursor");
        long offset = cursor.isEmpty() ? 0 : Long.parseUnsignedLong(cursor.replaceFirst("^0x", ""), 16);
        if (offset < 0) throw new IllegalArgumentException("type cursor is outside the supported row range");
        long visited = 0;
        while (iterator.hasNext() && visited < offset && System.nanoTime() < deadline) { iterator.next(); visited++; }
        if (visited < offset && iterator.hasNext()) throw new IllegalStateException("type cursor scan reached deadline");
        JsonArray rows = new JsonArray();
        int scanned = 0, limit = req.get("limit").getAsInt();
        while (iterator.hasNext() && scanned < 2000 && rows.size() < limit && System.nanoTime() < deadline) {
            monitor.checkCancelled();
            DataType type = iterator.next();
            scanned++;
            if (type.getPathName().toLowerCase(Locale.ROOT).contains(text(req, "contains").toLowerCase(Locale.ROOT))) rows.add(typeSummary(type));
        }
        out.add("types", rows);
        out.addProperty("scanned", scanned);
        out.addProperty("truncated", iterator.hasNext());
        if (iterator.hasNext()) out.addProperty("next_cursor", "0x" + Long.toHexString(visited + scanned));
    }

    private void inspectType(JsonObject req, JsonObject out) throws Exception {
        String path = text(options(req), "path");
        DataType type;
        if (!path.isEmpty()) type = resolveType(path);
        else {
            var data = currentProgram.getListing().getDefinedDataContaining(address(text(req, "address")));
            if (data == null) throw new IllegalArgumentException("no defined typed data contains this address");
            type = data.getDataType();
            out.addProperty("data_address", "0x" + data.getAddress());
        }
        JsonObject row = typeSummary(type);
        int limit = req.get("limit").getAsInt();
        if (type instanceof Composite composite) {
            JsonArray fields = new JsonArray();
            var components = composite.getDefinedComponents();
            for (int i = 0; i < components.length && i < limit; i++) {
                var component = components[i];
                JsonObject field = typeSummary(component.getDataType());
                field.addProperty("offset", component.getOffset());
                field.addProperty("length", component.getLength());
                field.addProperty("field", clip(component.getFieldName(), 512));
                field.addProperty("bitfield", component.isBitFieldComponent());
                field.addProperty("comment", clip(component.getComment(), 1024));
                fields.add(field);
            }
            row.add("fields", fields);
            row.addProperty("truncated", components.length > limit);
            row.addProperty("defined_components", components.length);
        } else if (type instanceof ghidra.program.model.data.Enum enumeration) {
            JsonArray values = new JsonArray();
            String[] names = enumeration.getNames();
            for (int i = 0; i < names.length && i < limit; i++) {
                JsonObject member = new JsonObject();
                member.addProperty("name", clip(names[i], 512));
                member.addProperty("value", Long.toString(enumeration.getValue(names[i])));
                values.add(member);
            }
            row.add("values", values);
            row.addProperty("truncated", names.length > limit);
        } else if (type instanceof Pointer pointer) {
            row.addProperty("pointee", pointer.getDataType() == null ? "unknown" : pointer.getDataType().getPathName());
        } else if (type instanceof ghidra.program.model.data.Array array) {
            row.addProperty("element_type", array.getDataType().getPathName());
            row.addProperty("elements", array.getNumElements());
        } else if (type instanceof TypeDef definition) row.addProperty("base_type", definition.getBaseDataType().getPathName());
        row.addProperty("authority", "saved analysis or explicitly cited user overlay; original source layout is not established");
        out.add("type", row);
    }

    private void variables(Function function, JsonObject out, int limit, long deadline) throws Exception {
        HighFunction high = decompile(function, deadline).getHighFunction();
        var symbols = high.getLocalSymbolMap().getSymbols();
        JsonArray rows = new JsonArray();
        while (symbols.hasNext() && rows.size() < limit && System.nanoTime() < deadline) {
            HighSymbol symbol = symbols.next();
            JsonObject row = typeSummary(symbol.getDataType());
            row.addProperty("variable", clip(symbol.getName(), 512));
            row.addProperty("parameter", symbol.isParameter());
            row.addProperty("storage", clip(symbol.getStorage().toString(), 512));
            row.addProperty("size", symbol.getSize());
            rows.add(row);
        }
        out.add("variables", rows);
        out.addProperty("truncated", symbols.hasNext());
        out.addProperty("type_provenance", "decompiler-recovered types, possibly refined by cited overlays; not original source types");
    }

    private void blocks(Function function, JsonObject out, int limit, long deadline) throws Exception {
        var iterator = new BasicBlockModel(currentProgram).getCodeBlocksContaining(function.getBody(), monitor);
        JsonArray rows = new JsonArray();
        while (iterator.hasNext() && rows.size() < limit && System.nanoTime() < deadline) {
            var block = iterator.next();
            JsonObject row = new JsonObject();
            row.addProperty("address", "0x" + block.getFirstStartAddress());
            row.addProperty("min", "0x" + block.getMinAddress());
            row.addProperty("max", "0x" + block.getMaxAddress());
            row.addProperty("flow", block.getFlowType().toString());
            JsonArray destinations = new JsonArray();
            var edges = block.getDestinations(monitor);
            while (edges.hasNext() && destinations.size() < 16 && System.nanoTime() < deadline) {
                var edge = edges.next();
                JsonObject destination = new JsonObject();
                destination.addProperty("address", "0x" + edge.getDestinationAddress());
                destination.addProperty("flow", edge.getFlowType().toString());
                destinations.add(destination);
            }
            row.add("destinations", destinations);
            row.addProperty("edges_truncated", edges.hasNext());
            rows.add(row);
        }
        out.add("blocks", rows);
        out.addProperty("truncated", iterator.hasNext());
        out.addProperty("provenance", "Ghidra BasicBlockModel on saved program listing");
    }

    private String opId(Function function, PcodeOp operation) {
        return "0x" + function.getEntryPoint() + "/0x" + operation.getSeqnum().getTarget() + ":" + operation.getSeqnum().getTime();
    }

    private String varId(Function function, Varnode node) {
        return "0x" + function.getEntryPoint() + "/" + node.getAddress() + ":" + node.getSize() + ":" +
            (node instanceof VarnodeAST ast ? ast.getUniqueId() : "free");
    }

    private JsonObject varnode(Function function, Varnode node) {
        JsonObject row = new JsonObject();
        row.addProperty("id", varId(function, node));
        row.addProperty("space", node.getAddress().getAddressSpace().getName());
        row.addProperty("offset", "0x" + Long.toUnsignedString(node.getOffset(), 16));
        row.addProperty("size", node.getSize());
        row.addProperty("constant", node.isConstant());
        if (node.isConstant()) row.addProperty("value", "0x" + Long.toUnsignedString(node.getOffset(), 16));
        HighVariable high = node.getHigh();
        if (high != null) {
            row.addProperty("variable", clip(high.getName(), 512));
            row.addProperty("type", high.getDataType().getPathName());
            if (high instanceof HighParam parameter) row.addProperty("parameter", parameter.getSlot());
        }
        if (node.getDef() != null) row.addProperty("definition", opId(function, node.getDef()));
        return row;
    }

    private JsonObject operation(Function function, PcodeOpAST operation) {
        JsonObject row = new JsonObject();
        row.addProperty("id", opId(function, operation));
        row.addProperty("function", "0x" + function.getEntryPoint());
        row.addProperty("address", "0x" + operation.getSeqnum().getTarget());
        row.addProperty("sequence", operation.getSeqnum().getTime());
        row.addProperty("opcode", operation.getMnemonic());
        row.addProperty("is_dead", operation.isDead());
        JsonArray inputs = new JsonArray();
        for (int i = 0; i < operation.getNumInputs() && i < 16; i++) inputs.add(varnode(function, operation.getInput(i)));
        row.add("inputs", inputs);
        row.addProperty("inputs_truncated", operation.getNumInputs() > 16);
        if (operation.getOutput() != null) row.add("output", varnode(function, operation.getOutput()));
        return row;
    }

    private class FlowOperation {
        final Function function;
        final PcodeOpAST operation;
        FlowOperation(Function function, PcodeOpAST operation) { this.function = function; this.operation = operation; }
    }

    private class FlowModel {
        final LinkedHashMap<String, FlowOperation> operations = new LinkedHashMap<>();
        final Map<String, Set<String>> backward = new HashMap<>();
        final Map<String, Set<String>> forward = new HashMap<>();
        final JsonArray edges = new JsonArray();
        final JsonArray unresolved = new JsonArray();
        boolean truncated = false;
        int functionCount = 0;
        int memoryEdges = 0;
        int callerCount = 0;
        final List<String> diagnostics = new ArrayList<>();
        final Map<String, String> loadKeys = new HashMap<>();
        // INDIRECTs at calls that were not given the slot's address: the value passes through.
        final Set<String> passThrough = new HashSet<>();
        int fieldKeys = 0;
        final Map<String, String> kinds = new HashMap<>();
        final Map<String, Integer> costs = new HashMap<>();
        void memoryEdge(String from, String to, String kind, long delta) {
            if (edges.size() >= 24000) { truncated = true; return; }
            backward.computeIfAbsent(to, key -> new LinkedHashSet<>()).add(from);
            forward.computeIfAbsent(from, key -> new LinkedHashSet<>()).add(to);
            kinds.put(from + ">" + to, kind);
            // Exact-offset hops are cheap; offset into a struct and writes after the use cost more.
            costs.merge(from + ">" + to, 1 + (delta != 0 ? 2 : 0) + (kind.endsWith("(after_use)") ? 4 : 0), Math::min);
            JsonObject row = new JsonObject();
            row.addProperty("from", from); row.addProperty("to", to); row.addProperty("kind", kind);
            if (delta != 0) row.addProperty("offset_delta", "0x" + Long.toHexString(delta));
            edges.add(row);
            memoryEdges++;
        }
        void edge(String from, String to, String kind, int input) {
            if (edges.size() >= 24000) { truncated = true; return; }
            backward.computeIfAbsent(to, key -> new LinkedHashSet<>()).add(from);
            forward.computeIfAbsent(from, key -> new LinkedHashSet<>()).add(to);
            JsonObject row = new JsonObject();
            row.addProperty("from", from); row.addProperty("to", to); row.addProperty("kind", kind);
            if (input >= 0) row.addProperty("input", input);
            edges.add(row);
        }
        void unknown(String id, String reason) {
            if (unresolved.size() >= 64) { truncated = true; return; }
            JsonObject row = new JsonObject(); row.addProperty("operation", id); row.addProperty("reason", reason); unresolved.add(row);
        }
    }

    private FlowModel flowModel(Function start, int maximumFunctions, long deadline) throws Exception {
        return flowModel(start, maximumFunctions, 0, deadline);
    }

    // The start function, up to `callers` of its direct callers (so a parameter meets the
    // argument it was given), then direct callees breadth first, within maximumFunctions.
    private FlowModel flowModel(Function start, int maximumFunctions, int callers, long deadline) throws Exception {
        FlowModel model = new FlowModel();
        LinkedHashMap<Address, List<FlowOperation>> functions = new LinkedHashMap<>();
        Set<Address> attempted = new HashSet<>();
        ArrayDeque<Function> pending = new ArrayDeque<>();
        ArrayDeque<Function> head = new ArrayDeque<>(), priority = new ArrayDeque<>();
        head.add(start);
        if (callers > 0) {
            Set<Address> seen = new LinkedHashSet<>();
            for (var reference : currentProgram.getReferenceManager().getReferencesTo(start.getEntryPoint())) {
                if (!reference.getReferenceType().isCall()) continue;
                Function caller = currentProgram.getFunctionManager().getFunctionContaining(reference.getFromAddress());
                if (caller != null && !caller.equals(start) && seen.add(caller.getEntryPoint())) head.add(caller);
                if (seen.size() >= callers) break;
            }
            model.callerCount = seen.size();
        }
        // The start and its callers first, then callees given a stack address, then the rest.
        while ((!head.isEmpty() || !priority.isEmpty() || !pending.isEmpty()) && attempted.size() < maximumFunctions && System.nanoTime() < deadline) {
            Function function = !head.isEmpty() ? head.removeFirst() : !priority.isEmpty() ? priority.removeFirst() : pending.removeFirst();
            if (!attempted.add(function.getEntryPoint())) continue;
            List<FlowOperation> captured = new ArrayList<>();
            HighFunction high;
            try { high = decompile(function, deadline).getHighFunction(); }
            catch (Exception error) {
                if (function.getEntryPoint().equals(start.getEntryPoint())) throw error;
                model.unknown("0x" + function.getEntryPoint(), "callee decompile refused: " + clip(error.toString(), 1024));
                continue;
            }
            var iterator = high.getPcodeOps();
            while (iterator.hasNext() && captured.size() < 4096 && model.operations.size() < 12000 && System.nanoTime() < deadline) {
                monitor.checkCancelled();
                PcodeOpAST operation = iterator.next();
                FlowOperation node = new FlowOperation(function, operation);
                captured.add(node); model.operations.put(opId(function, operation), node);
            }
            if (iterator.hasNext()) model.truncated = true;
            functions.put(function.getEntryPoint(), captured);
            // Callees given the address of a stack local (out-parameters) are where values in
            // memory come from, so they come before other callees in the function budget.
            if (maximumFunctions > 1) for (FlowOperation node : captured) {
                PcodeOpAST operation = node.operation;
                if (operation.getOpcode() != PcodeOp.CALL || operation.getNumInputs() == 0) continue;
                Function callee = currentProgram.getFunctionManager().getFunctionAt(operation.getInput(0).getAddress());
                if (callee == null || callee.isExternal() || attempted.contains(callee.getEntryPoint()) || pending.contains(callee)
                        || priority.contains(callee) || head.contains(callee)) continue;
                boolean outParameter = false;
                for (int i = 1; i < operation.getNumInputs(); i++) outParameter |= stackOffset(operation.getInput(i)) != null;
                if (outParameter && priority.size() < 16) priority.add(callee);
                else if (pending.size() < 16) pending.add(callee);
            }
        }
        if (!pending.isEmpty() || !priority.isEmpty() || !head.isEmpty()) model.truncated = true;
        model.functionCount = functions.size();
        for (Map.Entry<String, FlowOperation> entry : model.operations.entrySet()) {
            monitor.checkCancelled();
            if (System.nanoTime() >= deadline) { model.truncated = true; break; }
            FlowOperation node = entry.getValue();
            PcodeOpAST operation = node.operation;
            for (int i = 0; i < operation.getNumInputs() && i < 16; i++) {
                PcodeOp definition = operation.getInput(i).getDef();
                if (definition != null && model.operations.containsKey(opId(node.function, definition))) model.edge(opId(node.function, definition), entry.getKey(), "def_use", i);
            }
            if (operation.getOpcode() != PcodeOp.CALL && operation.getOpcode() != PcodeOp.CALLIND) continue;
            if (operation.getOpcode() == PcodeOp.CALLIND) { model.unknown(entry.getKey(), "indirect call target not resolved by this trace"); continue; }
            Function callee = currentProgram.getFunctionManager().getFunctionAt(operation.getInput(0).getAddress());
            List<FlowOperation> calleeOps = callee == null ? null : functions.get(callee.getEntryPoint());
            if (calleeOps == null) { model.unknown(entry.getKey(), "callee outside decompiled function budget or external/unavailable"); continue; }
            for (FlowOperation calleeNode : calleeOps) {
                if (System.nanoTime() >= deadline) { model.truncated = true; break; }
                PcodeOpAST calleeOperation = calleeNode.operation;
                String calleeId = opId(callee, calleeOperation);
                if (calleeOperation.getOpcode() == PcodeOp.RETURN && operation.getOutput() != null) model.edge(calleeId, entry.getKey(), "return_binding", -1);
                for (int i = 0; i < calleeOperation.getNumInputs() && i < 16; i++) {
                    HighVariable high = calleeOperation.getInput(i).getHigh();
                    if (!(high instanceof HighParam parameter)) continue;
                    int callerInput = parameter.getSlot() + 1;
                    if (callerInput >= operation.getNumInputs()) continue;
                    PcodeOp definition = operation.getInput(callerInput).getDef();
                    String from = definition == null ? entry.getKey() : opId(node.function, definition);
                    if (model.operations.containsKey(from)) model.edge(from, calleeId, "argument_binding", callerInput - 1);
                }
            }
        }
        memoryEdges(model, functions, deadline);
        return model;
    }

    // ---- values that travel through memory ---------------------------------------------------
    // Def-use stops where a value is written to memory and read back, or where only the
    // address of a stack local is passed on. These edges connect a write with the read (or
    // the address-of) of the same stack slot, and a store to base+offset with a load of the
    // same field, where base is one variable, or a parameter bound to the caller's argument.
    // They follow recovered addresses, not proven aliasing; each edge says what it matched.

    private boolean isStackBase(Varnode node) {
        var pointer = currentProgram.getCompilerSpec().getStackPointer();
        return node != null && node.isRegister() && pointer != null && node.getAddress().equals(pointer.getAddress());
    }

    private Long stackOffset(Varnode address) {
        PcodeOp definition = address.getDef();
        long extra = 0;
        for (int guard = 0; definition != null && guard < 8; guard++) {
            int code = definition.getOpcode();
            if (code == PcodeOp.PTRSUB && isStackBase(definition.getInput(0)) && definition.getInput(1).isConstant())
                return definition.getInput(1).getOffset() + extra;
            if ((code == PcodeOp.INT_ADD || code == PcodeOp.PTRSUB) && definition.getInput(1).isConstant()) {
                extra += definition.getInput(1).getOffset();
                definition = definition.getInput(0).getDef();
            } else if (code == PcodeOp.CAST || code == PcodeOp.COPY) definition = definition.getInput(0).getDef();
            else return null;
        }
        return null;
    }

    // How far past a stack address a callee's or caller's struct may extend (engine structs passed
    // by pointer are often a few hundred bytes).
    private static final long STRUCT_WINDOW = 0x200;

    // Callees (in the model) that return one of their parameters, by entry: slot.
    private final Map<Address, Integer> returnsParameter = new HashMap<>();

    private String identity(Function function, Varnode node, Map<String, String> aliases) {
        // A copy, a cast, or the result of a call that returns its own parameter is the same pointer.
        for (int guard = 0; guard < 8; guard++) {
            PcodeOp definition = node.getDef();
            if (definition == null) break;
            if (definition.getOpcode() == PcodeOp.CAST || definition.getOpcode() == PcodeOp.COPY) { node = definition.getInput(0); continue; }
            if (definition.getOpcode() == PcodeOp.CALL) {
                Integer slot = returnsParameter.get(definition.getInput(0).getAddress());
                if (slot != null && slot + 1 < definition.getNumInputs()) { node = definition.getInput(slot + 1); continue; }
            }
            break;
        }
        // Every address of one stack local is one identity, whichever PTRSUB formed it.
        Long local = stackOffset(node);
        if (local != null) return "stackaddr:" + function.getEntryPoint() + ":" + Long.toHexString(local);
        HighVariable high = node.getHigh();
        String key;
        if (high instanceof HighParam parameter) key = "param:" + function.getEntryPoint() + ":" + parameter.getSlot();
        else if (high != null && high.getRepresentative() != null) key = "var:" + varId(function, high.getRepresentative());
        else key = "node:" + varId(function, node);
        for (int guard = 0; aliases.containsKey(key) && guard < 8; guard++) key = aliases.get(key);
        return key;
    }

    // base+offset of an address expression, or null.
    private String fieldKey(Function function, Varnode address, Map<String, String> aliases) {
        long offset = 0;
        Varnode base = address;
        for (int guard = 0; guard < 8; guard++) {
            PcodeOp definition = base.getDef();
            if (definition == null) break;
            int code = definition.getOpcode();
            if ((code == PcodeOp.PTRSUB || code == PcodeOp.INT_ADD) && definition.getInput(1).isConstant()) {
                offset += definition.getInput(1).getOffset();
                base = definition.getInput(0);
            } else if (code == PcodeOp.PTRADD && definition.getInput(1).isConstant() && definition.getInput(2).isConstant()) {
                offset += definition.getInput(1).getOffset() * definition.getInput(2).getOffset();
                base = definition.getInput(0);
            } else if (code == PcodeOp.CAST || code == PcodeOp.COPY) base = definition.getInput(0);
            else break;
        }
        if (base.isConstant() || isStackBase(base)) return null;
        return identity(function, base, aliases) + "+0x" + Long.toHexString(offset);
    }

    // Within one function, a write at a later instruction than its use is only reached
    // through a loop or not at all; the edge says so instead of guessing.
    private String order(FlowModel model, String write, String use) {
        FlowOperation from = model.operations.get(write), to = model.operations.get(use);
        if (!from.function.equals(to.function)) return "";
        Address used = to.operation.getSeqnum().getTarget();
        if (to.operation.getOpcode() == PcodeOp.PTRSUB && to.operation.getOutput() != null) {
            // An address of a local is used where it is consumed (the latest such site).
            for (var iterator = to.operation.getOutput().getDescendants(); iterator.hasNext(); ) {
                Address site = iterator.next().getSeqnum().getTarget();
                if (site.compareTo(used) > 0) used = site;
            }
        }
        return from.operation.getSeqnum().getTarget().compareTo(used) <= 0 ? "" : "(after_use)";
    }

    private void memoryEdges(FlowModel model, Map<Address, List<FlowOperation>> functions, long deadline) {
        returnsParameter.clear();
        for (Map.Entry<Address, List<FlowOperation>> function : functions.entrySet()) {
            Integer slot = null;
            boolean consistent = true;
            for (FlowOperation node : function.getValue()) {
                if (node.operation.getOpcode() != PcodeOp.RETURN || node.operation.getNumInputs() < 2) continue;
                Varnode value = node.operation.getInput(1);
                while (value.getDef() != null && (value.getDef().getOpcode() == PcodeOp.CAST || value.getDef().getOpcode() == PcodeOp.COPY))
                    value = value.getDef().getInput(0);
                Integer returned = value.getHigh() instanceof HighParam parameter ? parameter.getSlot() : null;
                if (returned == null || (slot != null && !slot.equals(returned))) consistent = false;
                slot = returned;
            }
            if (consistent && slot != null) returnsParameter.put(function.getKey(), slot);
        }
        // A callee parameter is the caller's argument, for field identity across a call.
        Map<String, String> aliases = new HashMap<>();
        for (FlowOperation node : model.operations.values()) {
            PcodeOpAST operation = node.operation;
            if (operation.getOpcode() != PcodeOp.CALL) continue;
            Function callee = currentProgram.getFunctionManager().getFunctionAt(operation.getInput(0).getAddress());
            if (callee == null || !functions.containsKey(callee.getEntryPoint()) || callee.equals(node.function)) continue;
            for (int i = 1; i < operation.getNumInputs() && i < 16; i++) {
                String parameter = "param:" + callee.getEntryPoint() + ":" + (i - 1);
                if (!aliases.containsKey(parameter)) aliases.put(parameter, identity(node.function, operation.getInput(i), aliases));
            }
        }
        record Slot(String id, Function function, long offset, int size) {}
        Map<Address, List<Slot>> writes = new HashMap<>();
        Map<String, List<String>> fieldStores = new HashMap<>();
        List<Slot> addressOf = new ArrayList<>(), stackLoads = new ArrayList<>();
        Map<String, List<String>> fieldLoads = new HashMap<>();
        Map<String, List<Long>> escaped = new HashMap<>();
        for (FlowOperation node : model.operations.values()) {
            PcodeOpAST call = node.operation;
            if (call.getOpcode() != PcodeOp.CALL && call.getOpcode() != PcodeOp.CALLIND) continue;
            for (int i = 1; i < call.getNumInputs(); i++) {
                Long local = stackOffset(call.getInput(i));
                if (local != null) escaped.computeIfAbsent(node.function.getEntryPoint() + "@" + call.getSeqnum().getTarget(), key -> new ArrayList<>()).add(local);
            }
        }
        for (Map.Entry<String, FlowOperation> entry : model.operations.entrySet()) {
            if (System.nanoTime() >= deadline) { model.truncated = true; return; }
            FlowOperation node = entry.getValue();
            PcodeOpAST operation = node.operation;
            Address function = node.function.getEntryPoint();
            Varnode output = operation.getOutput();
            int code = operation.getOpcode();
            boolean write = output != null && output.getAddress().isStackAddress();
            if (write && code == PcodeOp.INDIRECT) {
                // A call writes a stack slot only if it was given an address at or below it.
                write = false;
                for (Long local : escaped.getOrDefault(function + "@" + operation.getSeqnum().getTarget(), List.of()))
                    write |= output.getOffset() >= local && output.getOffset() < local + STRUCT_WINDOW;
            }
            if (write)
                writes.computeIfAbsent(function, key -> new ArrayList<>()).add(new Slot(entry.getKey(), node.function, output.getOffset(), output.getSize()));
            else if (code == PcodeOp.INDIRECT) model.passThrough.add(entry.getKey());
            if (code == PcodeOp.PTRSUB && isStackBase(operation.getInput(0)) && operation.getInput(1).isConstant())
                addressOf.add(new Slot(entry.getKey(), node.function, operation.getInput(1).getOffset(), 0));
            if (code == PcodeOp.STORE && operation.getNumInputs() >= 3) {
                Long slot = stackOffset(operation.getInput(1));
                if (slot != null) writes.computeIfAbsent(function, key -> new ArrayList<>()).add(new Slot(entry.getKey(), node.function, slot, operation.getInput(2).getSize()));
                else {
                    String key = fieldKey(node.function, operation.getInput(1), aliases);
                    if (key != null) fieldStores.computeIfAbsent(key, item -> new ArrayList<>()).add(entry.getKey());
                }
            }
            if (code == PcodeOp.LOAD && operation.getNumInputs() >= 2) {
                Long slot = stackOffset(operation.getInput(1));
                if (slot != null) stackLoads.add(new Slot(entry.getKey(), node.function, slot, output == null ? 1 : output.getSize()));
                else {
                    String key = fieldKey(node.function, operation.getInput(1), aliases);
                    if (key != null) { fieldLoads.computeIfAbsent(key, item -> new ArrayList<>()).add(entry.getKey()); model.loadKeys.put(entry.getKey(), key); }
                }
            }
        }
        // The address of a stack local stands for what is stored in it (a struct passed by
        // pointer): writes from that offset up to STRUCT_WINDOW bytes beyond count.
        for (Slot pointer : addressOf) {
            for (Slot write : writes.getOrDefault(pointer.function().getEntryPoint(), List.of())) {
                long delta = write.offset() - pointer.offset();
                if (delta >= 0 && delta < STRUCT_WINDOW && !write.id().equals(pointer.id()))
                    model.memoryEdge(write.id(), pointer.id(), "stack_pointee" + order(model, write.id(), pointer.id()), delta);
            }
        }
        for (Slot load : stackLoads) {
            for (Slot write : writes.getOrDefault(load.function().getEntryPoint(), List.of())) {
                if (write.offset() < load.offset() + load.size() && load.offset() < write.offset() + write.size())
                    model.memoryEdge(write.id(), load.id(), "stack_store" + order(model, write.id(), load.id()), write.offset() - load.offset());
            }
        }
        for (Map.Entry<String, List<String>> loads : fieldLoads.entrySet()) {
            for (String store : fieldStores.getOrDefault(loads.getKey(), List.of()))
                for (String load : loads.getValue()) if (!store.equals(load)) model.memoryEdge(store, load, "field_store" + order(model, store, load), 0);
        }
        // A callee that stores through a pointer parameter writes the caller's stack local whose
        // address was the argument: link the store to the caller's INDIRECT on that slot.
        Map<String, List<Slot>> indirects = new HashMap<>();
        for (Map.Entry<String, FlowOperation> entry : model.operations.entrySet()) {
            PcodeOpAST operation = entry.getValue().operation;
            Varnode output = operation.getOutput();
            if (operation.getOpcode() == PcodeOp.INDIRECT && output != null && output.getAddress().isStackAddress())
                indirects.computeIfAbsent(entry.getValue().function.getEntryPoint() + "@" + operation.getSeqnum().getTarget(),
                    key -> new ArrayList<>()).add(new Slot(entry.getKey(), entry.getValue().function, output.getOffset(), output.getSize()));
        }
        for (Map.Entry<String, FlowOperation> entry : model.operations.entrySet()) {
            FlowOperation node = entry.getValue();
            PcodeOpAST call = node.operation;
            if (call.getOpcode() != PcodeOp.CALL) continue;
            Function callee = currentProgram.getFunctionManager().getFunctionAt(call.getInput(0).getAddress());
            if (callee == null || !functions.containsKey(callee.getEntryPoint()) || callee.equals(node.function)) continue;
            List<Slot> touched = indirects.getOrDefault(node.function.getEntryPoint() + "@" + call.getSeqnum().getTarget(), List.of());
            model.diagnostics.add("call " + call.getSeqnum().getTarget() + " -> " + callee.getEntryPoint() + " indirect stack slots " + touched.size());
            if (touched.isEmpty()) continue;
            for (int i = 1; i < call.getNumInputs() && i < 16; i++) {
                Long local = stackOffset(call.getInput(i));
                if (local == null) continue;
                String prefix = identity(node.function, call.getInput(i), aliases) + "+0x";
                model.diagnostics.add("  arg " + (i - 1) + " stack " + Long.toHexString(local) + " prefix " + prefix + " slots " + touched.stream().map(x -> Long.toHexString(x.offset()) + "/" + x.size()).toList());
                for (Map.Entry<String, List<String>> stores : fieldStores.entrySet()) {
                    if (!stores.getKey().startsWith(prefix)) continue;
                    long offset = Long.parseUnsignedLong(stores.getKey().substring(prefix.length()), 16);
                    for (Slot slot : touched) {
                        for (String store : stores.getValue()) {
                            PcodeOpAST write = model.operations.get(store).operation;
                            long start = local + offset, end = start + write.getInput(2).getSize();
                            // The callee's store overlaps the caller's slot.
                            if (start < slot.offset() + slot.size() && slot.offset() < end && model.operations.get(store).function.equals(callee))
                                model.memoryEdge(store, slot.id(), "out_param", offset);
                        }
                    }
                }
            }
        }
        model.fieldKeys = fieldLoads.size() + fieldStores.size();
        for (String key : fieldStores.keySet()) if (model.diagnostics.size() < 80) model.diagnostics.add("store key " + key);
    }

    private void flow(JsonObject req, Function function, JsonObject out, boolean trace, long deadline) throws Exception {
        JsonObject opts = options(req);
        int maximum = number(opts, "nodes", 80);
        FlowModel model = flowModel(function, trace ? number(opts, "functions", 1) : 1, trace ? number(opts, "callers", 0) : 0, deadline);
        Set<String> selected = new LinkedHashSet<>();
        boolean limited = model.truncated;
        int pageOffset = 0;
        if (!trace) {
            String cursor = text(req, "cursor");
            int offset = cursor.isEmpty() ? 0 : Integer.parseUnsignedInt(cursor.replaceFirst("^0x", ""), 16);
            if (offset < 0) throw new IllegalArgumentException("p-code cursor is outside the supported row range");
            pageOffset = offset;
            int index = 0;
            for (String id : model.operations.keySet()) if (index++ >= offset && selected.size() < maximum) selected.add(id);
            limited |= offset + selected.size() < model.operations.size();
        } else {
            String seed = text(opts, "seed");
            List<String> seeds = new ArrayList<>();
            for (Map.Entry<String, FlowOperation> entry : model.operations.entrySet()) {
                FlowOperation node = entry.getValue();
                if (seed.equals(entry.getKey())) seeds.add(entry.getKey());
                else if (seed.isEmpty() && node.function.getEntryPoint().equals(function.getEntryPoint()) &&
                         (node.operation.getOpcode() == PcodeOp.RETURN || node.operation.getSeqnum().getTarget().equals(address(text(req, "address"))))) seeds.add(entry.getKey());
                else if (!seed.isEmpty()) {
                    if (node.operation.getOutput() != null && seed.equals(varId(node.function, node.operation.getOutput()))) seeds.add(entry.getKey());
                    for (int i = 0; i < node.operation.getNumInputs() && i < 16; i++) if (seed.equals(varId(node.function, node.operation.getInput(i)))) { seeds.add(entry.getKey()); break; }
                }
            }
            if (seeds.isEmpty()) throw new IllegalArgumentException("trace seed not found; request pcode and pass an operation or varnode id");
            boolean backward = !text(opts, "direction").equals("forward");
            // argument=n follows one argument of the call at the address, not every input.
            if (opts.has("argument")) {
                int argument = number(opts, "argument", 0);
                List<String> narrowed = new ArrayList<>();
                for (String id : seeds) {
                    PcodeOpAST call = model.operations.get(id).operation;
                    if ((call.getOpcode() == PcodeOp.CALL || call.getOpcode() == PcodeOp.CALLIND) && argument + 1 < call.getNumInputs()) {
                        PcodeOp definition = call.getInput(argument + 1).getDef();
                        String from = definition == null ? null : opId(model.operations.get(id).function, definition);
                        if (from != null && model.operations.containsKey(from)) narrowed.add(from);
                        out.add("seed_argument", varnode(model.operations.get(id).function, call.getInput(argument + 1)));
                    }
                }
                if (narrowed.isEmpty()) throw new IllegalArgumentException("no call at this address has argument " + argument + " defined by recovered p-code");
                seeds = narrowed;
            }
            // Cheapest first (def-use 1, pass-through 0, memory hops by how direct they are),
            // so the node budget goes to the likeliest sources.
            PriorityQueue<Object[]> queue = new PriorityQueue<>(Comparator.comparingInt((Object[] item) -> (Integer) item[0]).thenComparingLong(item -> (Long) item[1]));
            long order = 0;
            Map<String, Integer> depths = new HashMap<>(), best = new HashMap<>();
            Map<String, String> parents = new HashMap<>();
            for (String id : seeds) { queue.add(new Object[] {0, order++, id}); depths.put(id, 0); best.put(id, 0); }
            Map<String, Set<String>> links = backward ? model.backward : model.forward;
            int depth = number(opts, "depth", 5);
            JsonArray stops = new JsonArray();
            while (!queue.isEmpty() && selected.size() < maximum && System.nanoTime() < deadline) {
                Object[] head = queue.poll();
                String id = (String) head[2];
                int cost = (Integer) head[0];
                if (!selected.add(id)) continue;
                int level = depths.get(id);
                Set<String> next = links.getOrDefault(id, Set.of());
                if (level >= depth) { if (!next.isEmpty()) { limited = true; stop(stops, model, id, "depth limit"); } continue; }
                if (next.isEmpty() && backward) stop(stops, model, id, null);
                // A call that cannot write the slot passes its value through at no depth cost.
                for (String item : next) {
                    if (selected.contains(item)) continue;
                    boolean free = model.passThrough.contains(item) || model.passThrough.contains(id);
                    String key = backward ? item + ">" + id : id + ">" + item;
                    int step = free ? 0 : model.costs.getOrDefault(key, 1);
                    if (best.containsKey(item) && best.get(item) <= cost + step) continue;
                    best.put(item, cost + step);
                    depths.put(item, free ? level : level + 1); parents.put(item, id);
                    queue.add(new Object[] {cost + step, order++, item});
                }
            }
            limited |= !queue.isEmpty();
            out.addProperty("direction", backward ? "backward" : "forward");
            // The constants the trace reached, each with its shortest path back to the seed.
            JsonArray constants = new JsonArray();
            for (String id : selected) {
                PcodeOpAST operation = model.operations.get(id).operation;
                int code = operation.getOpcode();
                if (code == PcodeOp.PTRSUB || code == PcodeOp.INDIRECT || code == PcodeOp.CALL || code == PcodeOp.CALLIND) continue;
                for (int i = 0; i < operation.getNumInputs() && i < 16; i++) {
                    Varnode input = operation.getInput(i);
                    // Structural operands are not values: a space id, a SUBPIECE byte offset, a
                    // PTRADD element size, or the offset of address arithmetic.
                    if (!input.isConstant() || ((code == PcodeOp.LOAD || code == PcodeOp.STORE) && i == 0)
                            || (code == PcodeOp.SUBPIECE && i == 1) || (code == PcodeOp.PTRADD && i == 2)
                            || (code == PcodeOp.INT_ADD && i == 1 && isAddressArithmetic(operation))) continue;
                    if (constants.size() >= 32) break;
                    JsonObject row = new JsonObject();
                    row.addProperty("operation", id);
                    row.addProperty("address", "0x" + operation.getSeqnum().getTarget());
                    row.addProperty("opcode", operation.getMnemonic());
                    row.addProperty("input", i);
                    row.addProperty("value", "0x" + Long.toUnsignedString(input.getOffset(), 16));
                    row.addProperty("decimal", Long.toString(input.getOffset()));
                    row.addProperty("size", input.getSize());
                    if (code == PcodeOp.PIECE) row.addProperty("part", i == 0 ? "high bytes" : "low bytes");
                    JsonArray path = new JsonArray();
                    String step = id;
                    for (int guard = 0; step != null && guard < 64; guard++) {
                        JsonObject hop = new JsonObject();
                        hop.addProperty("operation", step);
                        String parent = parents.get(step);
                        if (parent != null) {
                            String kind = backward ? model.kinds.get(step + ">" + parent) : model.kinds.get(parent + ">" + step);
                            hop.addProperty("via", kind == null ? "def_use" : kind);
                        }
                        path.add(hop);
                        step = parent;
                    }
                    row.add("path_to_seed", path);
                    row.addProperty("after_use", path.toString().contains("(after_use)"));
                    constants.add(row);
                }
            }
            // Answers written before their use come first.
            List<JsonElement> ranked = new ArrayList<>(constants.asList());
            ranked.sort(Comparator.comparing((JsonElement item) -> item.getAsJsonObject().get("after_use").getAsBoolean())
                .thenComparing(item -> item.getAsJsonObject().getAsJsonArray("path_to_seed").size()));
            JsonArray sorted = new JsonArray();
            ranked.forEach(sorted::add);
            out.add("constants", sorted);
            out.add("stops", stops);
            // Only the calls this trace passed through, not every call in the function.
            JsonArray relevant = new JsonArray();
            for (JsonElement element : model.unresolved)
                if (selected.contains(text(element.getAsJsonObject(), "operation"))) relevant.add(element);
            while (model.unresolved.size() > 0) model.unresolved.remove(0);
            model.unresolved.addAll(relevant);
        }
        JsonArray operations = new JsonArray(), edges = new JsonArray();
        Set<String> retained = new HashSet<>();
        int payloadBytes = 0;
        boolean brief = trace && opts.has("brief") && opts.get("brief").getAsBoolean();
        out.addProperty("selected_operations", selected.size());
        if (!brief) for (String id : selected) {
            FlowOperation node = model.operations.get(id);
            JsonObject row = operation(node.function, node.operation);
            int bytes = json.toJson(row).getBytes(StandardCharsets.UTF_8).length;
            if (payloadBytes + bytes > 72000) { limited = true; break; }
            payloadBytes += bytes; operations.add(row); retained.add(id);
        }
        for (JsonElement element : model.edges) {
            JsonObject edge = element.getAsJsonObject();
            if (retained.contains(text(edge, "from")) && retained.contains(text(edge, "to"))) {
                int bytes = json.toJson(edge).getBytes(StandardCharsets.UTF_8).length;
                if (edges.size() >= 800 || payloadBytes + bytes > 72000) { limited = true; break; }
                payloadBytes += bytes; edges.add(edge);
            }
        }
        if (!trace && pageOffset + operations.size() < model.operations.size()) out.addProperty("next_cursor", "0x" + Integer.toHexString(pageOffset + operations.size()));
        out.add("operations", operations); out.add("edges", edges); out.add("unresolved_calls", model.unresolved);
        out.addProperty("functions_decompiled", model.functionCount);
        out.addProperty("memory_edges", model.memoryEdges);
        if (opts.has("debug")) { JsonArray d = new JsonArray(); model.diagnostics.forEach(d::add); out.add("diagnostics", d); }
        out.addProperty("captured_operations", model.operations.size());
        out.addProperty("payload_utf8_bytes", payloadBytes);
        out.addProperty("truncated", limited || edges.size() >= 800);
        out.addProperty("provenance", "Ghidra decompiler HighFunction p-code; operation IDs cite function, instruction and sequence");
        out.addProperty("runtime_observed", false);
        out.addProperty("limitations", "Def-use, direct-call bindings and memory edges: stack_pointee (a write into a stack local whose address is passed on), stack_store (a write to and a read from one stack slot) and field_store (a store and a load of the same base+offset, base followed into callers through parameters). Memory edges match recovered addresses, ignore instruction order and do not prove aliasing; indirect calls, call side effects on memory and runtime path feasibility remain unknown.");
    }

    private boolean isAddressArithmetic(PcodeOpAST operation) {
        Varnode output = operation.getOutput();
        if (output == null) return false;
        for (var iterator = output.getDescendants(); iterator.hasNext(); ) {
            PcodeOp use = iterator.next();
            if ((use.getOpcode() == PcodeOp.LOAD || use.getOpcode() == PcodeOp.STORE) && use.getInput(1) == output) return true;
        }
        return false;
    }

    private void stop(JsonArray stops, FlowModel model, String id, String reason) {
        if (stops.size() >= 32) return;
        PcodeOpAST operation = model.operations.get(id).operation;
        if (reason == null) {
            int code = operation.getOpcode();
            boolean constantsOnly = true;
            for (int i = 0; i < operation.getNumInputs(); i++) if (!operation.getInput(i).isConstant()) constantsOnly = false;
            if (constantsOnly) return;  // a constant is an answer, not a stop
            String parameter = null;
            for (int i = 0; i < operation.getNumInputs(); i++)
                if (operation.getInput(i).getHigh() instanceof HighParam high) parameter = "parameter " + high.getSlot() + " of " + model.operations.get(id).function.getName();
            if (parameter != null) reason = parameter + " (callers outside the trace's function budget)";
            else if (code == PcodeOp.LOAD) reason = "load of " + model.loadKeys.getOrDefault(id, "memory") + " with no matching store in the traced functions";
            else if (code == PcodeOp.CALL) reason = "result of a call outside the function budget";
            else if (code == PcodeOp.CALLIND) reason = "result of an indirect call";
            else if (code == PcodeOp.INDIRECT) reason = "value the call at 0x" + operation.getSeqnum().getTarget() + " may have changed";
            else if (code == PcodeOp.PTRSUB) reason = "address of a stack local with no write to it in the function";
            else reason = "inputs have no recovered definition (registers or globals on entry)";
        }
        JsonObject row = new JsonObject();
        row.addProperty("operation", id);
        row.addProperty("address", "0x" + operation.getSeqnum().getTarget());
        row.addProperty("opcode", operation.getMnemonic());
        row.addProperty("reason", reason);
        stops.add(row);
    }

    private void dossier(Function function, JsonObject out, int limit, long deadline) throws Exception {
        JsonArray instructions = new JsonArray(), callers = new JsonArray(), callees = new JsonArray();
        JsonArray dataReferences = new JsonArray(), strings = new JsonArray();
        Set<Address> stringAddresses = new HashSet<>();
        var listing = currentProgram.getListing().getInstructions(function.getBody(), true);
        int scanned = 0, referencesScanned = 0;
        int previewLimit = Math.min(limit, 40), referenceLimit = Math.min(limit, 64), stringLimit = Math.min(limit, 32);
        boolean calleesTruncated = false, dataTruncated = false, stringsTruncated = false, referenceScanTruncated = false;
        while (listing.hasNext() && scanned < 2000 && referencesScanned < 8000 && System.nanoTime() < deadline) {
            monitor.checkCancelled();
            var instruction = listing.next();
            scanned++;
            if (instructions.size() < previewLimit) {
                JsonObject row = new JsonObject(); row.addProperty("address", "0x" + instruction.getAddress()); row.addProperty("instruction", clip(instruction.toString(), 1024)); instructions.add(row);
            }
            for (var reference : instruction.getReferencesFrom()) {
                if (referencesScanned >= 8000 || System.nanoTime() >= deadline) { referenceScanTruncated = true; break; }
                referencesScanned++;
                if (reference.getReferenceType().isCall()) {
                    if (callees.size() < referenceLimit) {
                        JsonObject row = new JsonObject(); row.addProperty("from", "0x" + reference.getFromAddress()); row.addProperty("to", "0x" + reference.getToAddress()); row.addProperty("type", reference.getReferenceType().toString()); callees.add(row);
                    } else calleesTruncated = true;
                }
                if (!reference.getReferenceType().isData()) continue;
                var data = currentProgram.getListing().getDefinedDataContaining(reference.getToAddress());
                if (dataReferences.size() < referenceLimit) {
                    JsonObject row = new JsonObject();
                    row.addProperty("from", "0x" + reference.getFromAddress()); row.addProperty("to", "0x" + reference.getToAddress()); row.addProperty("type", reference.getReferenceType().toString());
                    if (data != null) {
                        row.addProperty("data_address", "0x" + data.getAddress()); row.addProperty("data_type", clip(data.getDataType().getPathName(), 256));
                        if (data.getLength() <= 1024) {
                            String value = data.getDefaultValueRepresentation(); row.addProperty("value", clip(value, 256)); row.addProperty("value_truncated", value != null && value.length() > 256);
                        } else row.addProperty("value_truncated", true);
                    }
                    dataReferences.add(row);
                } else dataTruncated = true;
                if (data != null && data.hasStringValue() && stringAddresses.add(data.getAddress())) {
                    if (strings.size() < stringLimit) {
                        JsonObject row = new JsonObject();
                        row.addProperty("from", "0x" + reference.getFromAddress()); row.addProperty("to", "0x" + reference.getToAddress()); row.addProperty("type", reference.getReferenceType().toString());
                        row.addProperty("data_address", "0x" + data.getAddress()); row.addProperty("data_type", clip(data.getDataType().getPathName(), 256));
                        if (data.getLength() <= 1024) {
                            String value = data.getDefaultValueRepresentation(); row.addProperty("value", clip(value, 512)); row.addProperty("value_truncated", value != null && value.length() > 512);
                        } else { row.addProperty("value", "not materialized: string exceeds 1024 bytes"); row.addProperty("value_truncated", true); }
                        strings.add(row);
                    } else stringsTruncated = true;
                }
            }
        }
        boolean scanTruncated = listing.hasNext() || referenceScanTruncated;
        calleesTruncated |= scanTruncated; dataTruncated |= scanTruncated; stringsTruncated |= scanTruncated;
        var incoming = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint());
        int entryReferencesScanned = 0;
        while (incoming.hasNext() && callers.size() < referenceLimit && entryReferencesScanned < 2000 && System.nanoTime() < deadline) {
            var reference = incoming.next();
            entryReferencesScanned++;
            if (reference.getReferenceType().isCall()) { JsonObject row = new JsonObject(); row.addProperty("from", "0x" + reference.getFromAddress()); row.addProperty("type", reference.getReferenceType().toString()); callers.add(row); }
        }
        out.add("instructions", instructions); out.add("callers", callers); out.add("callees", callees);
        out.add("data_refs", dataReferences); out.add("referenced_strings", strings);
        out.addProperty("total_instructions_scanned", scanned); out.addProperty("instruction_count_complete", !listing.hasNext());
        out.addProperty("references_scanned", referencesScanned); out.addProperty("entry_references_scanned", entryReferencesScanned);
        out.addProperty("instructions_truncated", scanned > instructions.size() || scanTruncated);
        out.addProperty("listing_scan_truncated", scanTruncated);
        out.addProperty("callers_truncated", incoming.hasNext()); out.addProperty("callees_truncated", calleesTruncated);
        out.addProperty("data_refs_truncated", dataTruncated); out.addProperty("referenced_strings_truncated", stringsTruncated);
        out.addProperty("caller_scope", "call references to the exact function entry; excludes interior and data references");
        out.addProperty("string_scope", "one preview per defined string with its first observed site in the bounded instruction scan");
        blocks(function, out, Math.min(limit, 40), deadline);
        out.add("blocks_truncated", out.remove("truncated"));
        var result = decompile(function, deadline);
        String c = result.getDecompiledFunction().getC();
        out.addProperty("c", clip(c, 16000)); out.addProperty("c_truncated", c.length() > 16000);
        out.addProperty("provenance", "saved Ghidra listing, per-instruction references/defined strings and decompiler; bounded results do not enumerate every reference to the entire function body");
        String[] arrays = {"instructions", "callers", "callees", "data_refs", "referenced_strings", "blocks"};
        int payload = json.toJson(out).getBytes(StandardCharsets.UTF_8).length;
        boolean payloadTruncated = false;
        while (payload > 78000) {
            String selected = null; int largest = 0;
            for (String name : arrays) {
                JsonArray rows = out.getAsJsonArray(name);
                if (rows.size() == 0) continue;
                int bytes = json.toJson(rows.get(rows.size() - 1)).getBytes(StandardCharsets.UTF_8).length;
                if (bytes > largest) { selected = name; largest = bytes; }
            }
            if (selected == null) { out.addProperty("c", clip(c, 8000)); out.addProperty("c_truncated", true); break; }
            JsonArray rows = out.getAsJsonArray(selected); rows.remove(rows.size() - 1);
            out.addProperty(selected + "_truncated", true); payloadTruncated = true;
            payload = json.toJson(out).getBytes(StandardCharsets.UTF_8).length;
        }
        boolean incomplete = payloadTruncated;
        for (String flag : new String[] {"instructions_truncated", "listing_scan_truncated", "callers_truncated", "callees_truncated", "data_refs_truncated", "referenced_strings_truncated", "blocks_truncated", "c_truncated"}) incomplete |= out.get(flag).getAsBoolean();
        out.addProperty("listing_truncated", incomplete); out.addProperty("truncated", incomplete);
        out.addProperty("payload_utf8_bytes", json.toJson(out).getBytes(StandardCharsets.UTF_8).length);
    }

    private void typeEdit(String addressText, JsonObject opts, long deadline) throws Exception {
        if (System.nanoTime() >= deadline) throw new IllegalStateException("overlay edit deadline reached; edit not completed");
        monitor.checkCancelled();
        String kind = text(opts, "kind");
        if (text(opts, "source").isBlank()) throw new IllegalArgumentException("type edit needs a cited source");
        int transaction = currentProgram.startTransaction("RusticRE in-memory cited overlay");
        boolean success = false;
        try {
            if (kind.equals("batch")) {
                JsonArray edits = opts.getAsJsonArray("edits");
                if (edits == null || edits.size() == 0 || edits.size() > 200) throw new IllegalArgumentException("batch needs 1..200 normalized edits");
                int completed = 0;
                for (JsonElement value : edits) {
                    if (System.nanoTime() >= deadline) throw new IllegalStateException("batch deadline reached after " + completed + "/" + edits.size() + " edits; entire batch rolled back");
                    JsonObject edit = value.getAsJsonObject();
                    JsonObject child = edit.getAsJsonObject("options").deepCopy();
                    if (text(child, "kind").equals("batch")) throw new IllegalArgumentException("nested batches are refused");
                    if (text(child, "source").isBlank()) child.addProperty("source", text(opts, "source"));
                    typeEdit(text(edit, "address"), child, deadline);
                    completed++;
                }
            } else if (kind.equals("struct")) {
                String path = text(opts, "path");
                int split = path.lastIndexOf('/');
                var manager = currentProgram.getDataTypeManager();
                StructureDataType structure = new StructureDataType(new CategoryPath(split == 0 ? "/" : path.substring(0, split)), path.substring(split + 1), number(opts, "size", 0), manager);
                List<int[]> occupied = new ArrayList<>();
                for (JsonElement element : opts.getAsJsonArray("fields")) {
                    JsonObject field = element.getAsJsonObject();
                    DataType type = resolveType(text(field, "type"));
                    int length = number(field, "length", type.getLength());
                    int offset = number(field, "offset", 0);
                    if (length <= 0 || offset + length > structure.getLength()) throw new IllegalArgumentException("field exceeds explicit structure size");
                    for (int[] range : occupied) if (offset < range[1] && offset + length > range[0]) throw new IllegalArgumentException("structure fields overlap; use a separate union type rather than guessing layout");
                    occupied.add(new int[] { offset, offset + length });
                    structure.replaceAtOffset(offset, type, length, text(field, "name"), "source: " + text(opts, "source"));
                }
                DataType existing = manager.getDataType(path);
                if (existing != null && !existing.isEquivalent(structure)) throw new IllegalArgumentException("different type already exists at path; choose a new overlay path");
                manager.addDataType(structure, DataTypeConflictHandler.KEEP_HANDLER);
            } else if (kind.startsWith("function_")) {
                Address entry = address(addressText);
                var listing = currentProgram.getListing();
                if (listing.getInstructionAt(entry) == null) throw new IllegalArgumentException("function entry must already be a decoded instruction; no guessed boundary is accepted");
                String[] expected = text(opts, "expect").trim().split("\\s+");
                if (expected.length < 1 || expected.length > 64) throw new IllegalArgumentException("function edit needs 1..64 exact expected bytes");
                byte[] actual = new byte[expected.length];
                if (currentProgram.getMemory().getBytes(entry, actual) != actual.length) throw new IllegalArgumentException("entry expected bytes are not fully initialized");
                for (int i = 0; i < expected.length; i++) {
                    if (!expected[i].matches("[0-9a-fA-F]{2}") || (actual[i] & 255) != Integer.parseInt(expected[i], 16)) throw new IllegalArgumentException("PROLOGUE MISMATCH; function edit refused");
                }
                var manager = currentProgram.getFunctionManager();
                Function existing = manager.getFunctionAt(entry);
                if (kind.equals("function_delete")) {
                    if (existing == null || !manager.removeFunction(entry)) throw new IllegalArgumentException("no function exists at the exact entry for deletion");
                } else {
                    AddressSet body = new AddressSet();
                    JsonArray ranges = opts.getAsJsonArray("ranges");
                    if (ranges == null || ranges.size() == 0 || ranges.size() > 64) throw new IllegalArgumentException("function needs 1..64 explicit inclusive ranges");
                    for (JsonElement value : ranges) {
                        JsonObject range = value.getAsJsonObject();
                        Address start = address(text(range, "start")), end = address(text(range, "end"));
                        if (start.compareTo(end) > 0) throw new IllegalArgumentException("function range end precedes start");
                        var block = currentProgram.getMemory().getBlock(start);
                        if (block == null || !block.isInitialized() || !block.isExecute() || !block.contains(end)) throw new IllegalArgumentException("function ranges must stay inside initialized executable memory blocks");
                        var first = listing.getInstructionAt(start);
                        var last = listing.getInstructionContaining(end);
                        if (first == null || last == null || !last.getMaxAddress().equals(end)) throw new IllegalArgumentException("function range boundaries must match decoded instruction boundaries");
                        body.addRange(start, end);
                    }
                    if (!body.contains(entry)) throw new IllegalArgumentException("function body must contain its entry");
                    var overlapping = manager.getFunctionsOverlapping(body);
                    while (overlapping.hasNext()) if (!overlapping.next().getEntryPoint().equals(entry)) throw new IllegalArgumentException("body overlaps another function; correct its cited definition explicitly first");
                    if (kind.equals("function_create")) {
                        if (existing != null) throw new IllegalArgumentException("function already exists at entry; use function_body for an explicit correction");
                        manager.createFunction(text(opts, "name").isEmpty() ? null : text(opts, "name"), entry, body, SourceType.USER_DEFINED);
                    } else if (kind.equals("function_body")) {
                        if (existing == null) throw new IllegalArgumentException("no function exists at entry; use function_create");
                        existing.setBody(body);
                        if (!text(opts, "name").isEmpty()) existing.setName(text(opts, "name"), SourceType.USER_DEFINED);
                    } else throw new IllegalArgumentException("unknown function edit kind");
                }
            } else {
                Address addr = address(addressText);
                Function function = currentProgram.getFunctionManager().getFunctionContaining(addr);
                if (kind.equals("apply")) DataUtilities.createData(currentProgram, addr, resolveType(text(opts, "type")), -1, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
                else if (kind.equals("comment")) currentProgram.getListing().setComment(addr, ghidra.program.model.listing.CommentType.PLATE, text(opts, "comment") + "\nsource: " + text(opts, "source"));
                else {
                    if (function == null) throw new IllegalArgumentException("no function contains edit address");
                    if (kind.equals("rename")) function.setName(text(opts, "name"), SourceType.USER_DEFINED);
                    else if (kind.equals("signature")) {
                        var signature = new FunctionSignatureParser(currentProgram.getDataTypeManager(), null).parse(function.getSignature(), text(opts, "prototype"));
                        var command = new ApplyFunctionSignatureCmd(function.getEntryPoint(), signature, SourceType.USER_DEFINED);
                        if (!command.applyTo(currentProgram, monitor)) throw new IllegalStateException(command.getStatusMsg());
                    } else if (kind.equals("variable")) {
                        HighFunction high = decompile(function, deadline).getHighFunction();
                        var symbols = high.getLocalSymbolMap().getSymbols();
                        HighSymbol selected = null;
                        while (symbols.hasNext()) { HighSymbol symbol = symbols.next(); if (symbol.getName().equals(text(opts, "variable"))) { if (selected != null) throw new IllegalArgumentException("variable name is ambiguous"); selected = symbol; } }
                        if (selected == null) throw new IllegalArgumentException("variable not found in recovered symbol map");
                        HighFunctionDBUtil.updateDBVariable(selected, text(opts, "name").isEmpty() ? null : text(opts, "name"), resolveType(text(opts, "type")), SourceType.USER_DEFINED);
                    } else throw new IllegalArgumentException("unknown type edit kind");
                }
            }
            success = true;
        } finally {
            currentProgram.endTransaction(transaction, success);
            if (decompiler != null) decompiler.flushCache();
        }
    }

    private static final String STATE_OPTION = "overlay_state";

    private String overlayState() {
        return currentProgram.getOptions("RusticRE").getString(STATE_OPTION, "");
    }

    // Applies cited overlay records to a working copy this client owns, in order, and
    // records which state the program now holds. The caller saves the program; a
    // failure rolls back the record that failed and stops, naming it.
    private void applyOverlays(JsonObject req, JsonObject out, long deadline) throws Exception {
        String file = text(req, "edits_file");
        if (file.isEmpty()) throw new IllegalArgumentException("apply_overlays needs edits_file");
        JsonObject batch = JsonParser.parseString(Files.readString(Path.of(file), StandardCharsets.UTF_8)).getAsJsonObject();
        JsonArray records = batch.getAsJsonArray("edits");
        monitor.initialize(records.size());
        // One outer transaction: a record that fails rolls back the whole call, so the
        // working copy is either at the new state or unchanged.
        int transaction = currentProgram.startTransaction("RusticRE overlays");
        boolean success = false;
        try {
            int index = 0;
            for (JsonElement element : records) {
                index++;
                monitor.checkCancelled();
                if (System.nanoTime() >= deadline) throw new IllegalStateException("overlay apply incomplete at " + index + "/" + records.size() + "; deadline reached; nothing applied");
                JsonObject edit = element.getAsJsonObject();
                try { typeEdit(text(edit, "address"), edit.getAsJsonObject("options"), deadline); }
                catch (Exception error) {
                    throw new IllegalArgumentException("overlay record " + index + "/" + records.size() + " (" + text(edit, "id") + ") refused, nothing applied: " + error.getMessage(), error);
                }
                if (index % 64 == 0) { monitor.setMessage("overlays " + index + "/" + records.size()); monitor.setProgress(index); }
            }
            Options options = currentProgram.getOptions("RusticRE");
            options.setString(STATE_OPTION, json.toJson(batch.getAsJsonObject("state")));
            success = true;
        } finally { currentProgram.endTransaction(transaction, success); }
        out.addProperty("applied", records.size());
        out.addProperty("overlay_state", overlayState());
    }

    private void write(Path path, JsonObject body) throws Exception {
        Path temp = path.resolveSibling(path.getFileName() + ".tmp");
        Files.writeString(temp, json.toJson(body), StandardCharsets.UTF_8);
        Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private JsonObject queryError(String id, Exception error) {
        JsonObject response = new JsonObject();
        response.addProperty("id", id);
        response.addProperty("ok", false);
        response.addProperty("program", currentProgram.getName());
        response.addProperty("sha256", currentProgram.getExecutableSHA256());
        response.addProperty("image_base", "0x" + currentProgram.getImageBase());
        response.addProperty("address_kind", "VA");
        response.addProperty("error", error.toString());
        boolean recoverable = error instanceof IllegalArgumentException;
        response.addProperty("recoverable", recoverable);
        if (recoverable) {
            String message = error.getMessage() == null ? "" : error.getMessage().toLowerCase(Locale.ROOT);
            response.addProperty("error_kind", message.startsWith("no ") || message.contains("not found") || message.startsWith("unknown type:") ? "not_found" : "invalid_request");
        } else response.addProperty("error_kind", "backend_failure");
        if (!recoverable && decompiler != null) { giveBack(currentProgram, decompiler, false); decompiler = null; }
        return response;
    }

    private String text(JsonObject req, String key) {
        return req.has(key) ? req.get(key).getAsString() : "";
    }

    // VA by default; rva:/va: say which. An RVA is relative to the program's image base.
    private Address address(String value) {
        String text = value.trim();
        if (text.startsWith("rva:")) {
            long offset = Long.parseUnsignedLong(text.substring(4).replaceFirst("^0[xX]", ""), 16);
            return currentProgram.getImageBase().add(offset);
        }
        if (text.startsWith("va:")) text = text.substring(3);
        Address result = toAddr(text.replaceFirst("^0[xX]", ""));
        if (result == null) throw new IllegalArgumentException("not an address in this program: " + value);
        return result;
    }

    private JsonObject function(Function f) {
        JsonObject row = new JsonObject();
        row.addProperty("address", "0x" + f.getEntryPoint());
        String name = f.getName();
        String prototype = f.getPrototypeString(false, false);
        row.addProperty("name", name.substring(0, Math.min(name.length(), 512)));
        row.addProperty("signature", prototype.substring(0, Math.min(prototype.length(), 2048)));
        var ranges = f.getBody().getAddressRanges();
        JsonArray body = new JsonArray();
        while (ranges.hasNext() && body.size() < 200) body.add(ranges.next().toString());
        row.add("body", body);
        row.addProperty("body_truncated", ranges.hasNext());
        return row;
    }

    private JsonObject query(JsonObject req) throws Exception {
        JsonObject out = new JsonObject();
        out.addProperty("id", text(req, "id"));
        out.addProperty("program", currentProgram.getName());
        out.addProperty("sha256", currentProgram.getExecutableSHA256());
        out.addProperty("image_base", "0x" + currentProgram.getImageBase());
        out.addProperty("address_kind", "VA");
        String action = text(req, "action");
        int limit = req.get("limit").getAsInt();
        int seconds = req.get("timeout_s").getAsInt();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
        String expected = text(req, "expected_sha256");
        if (!expected.isEmpty() && !expected.equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("program SHA-256 " + currentProgram.getExecutableSHA256() + " differs from the target build " + expected);
        out.addProperty("overlay_state", overlayState());
        if (action.equals("overlay_state")) {
            out.addProperty("changed", currentProgram.isChanged()); out.addProperty("ok", true); return out;
        }
        if (action.equals("apply_overlays")) {
            applyOverlays(req, out, deadline); out.addProperty("ok", true); return out;
        }
        if (action.equals("types")) {
            types(req, out, deadline); out.addProperty("ok", true); return out;
        }
        if (action.equals("type")) {
            inspectType(req, out); out.addProperty("ok", true); return out;
        }
        if (action.equals("data")) {
            data(req, out, deadline); out.addProperty("ok", true); return out;
        }
        if (action.equals("scan")) {
            scan(req, out, deadline); out.addProperty("ok", true); return out;
        }
        if (action.equals("type_edit")) {
            // Run contained, this is a dry run: the engine rolls the edit back afterwards.
            typeEdit(text(req, "address"), options(req), deadline);
            out.addProperty("edit_validated", true);
            out.addProperty("edits_applied", text(options(req), "kind").equals("batch") ? options(req).getAsJsonArray("edits").size() : 1);
            out.addProperty("ok", true); return out;
        }
        if (Set.of("variables", "dossier", "blocks", "pcode", "trace").contains(action)) {
            Function function = currentProgram.getFunctionManager().getFunctionContaining(address(text(req, "address")));
            if (function == null) throw new IllegalArgumentException("no analysed function contains this address");
            out.add("function", function(function));
            switch (action) {
                case "variables": variables(function, out, limit, deadline); break;
                case "dossier": dossier(function, out, limit, deadline); break;
                case "blocks": blocks(function, out, limit, deadline); break;
                case "pcode": flow(req, function, out, false, deadline); break;
                case "trace": flow(req, function, out, true, deadline); break;
            }
            out.addProperty("ok", true); return out;
        }
        var fm = currentProgram.getFunctionManager();
        if (action.equals("functions")) {
            String cursor = text(req, "cursor");
            var iterator = cursor.isEmpty() ? fm.getFunctions(true) : fm.getFunctions(address(cursor), true);
            JsonArray rows = new JsonArray();
            Address last = null;
            int scanned = 0;
            while (iterator.hasNext() && scanned < 2000 && rows.size() < limit && System.nanoTime() < deadline) {
                Function f = iterator.next();
                last = f.getEntryPoint();
                scanned++;
                if (f.getName().toLowerCase().contains(text(req, "contains").toLowerCase())) rows.add(function(f));
            }
            boolean more = iterator.hasNext();
            out.add("functions", rows);
            out.addProperty("scanned", scanned);
            out.addProperty("truncated", more);
            if (more && last != null) out.addProperty("next_cursor", "0x" + last.next());
        } else {
            Address addr = address(text(req, "address"));
            if (action.equals("xrefs")) {
                var refs = currentProgram.getReferenceManager().getReferencesTo(addr);
                JsonArray rows = new JsonArray();
                String cursor = text(req, "cursor");
                long offset = cursor.isEmpty() ? 0 : Long.parseUnsignedLong(cursor.replaceFirst("^0x", ""), 16);
                if (offset < 0) throw new IllegalArgumentException("xref cursor is outside the supported row range");
                long skipped = 0;
                while (refs.hasNext() && skipped < offset && System.nanoTime() < deadline) { refs.next(); skipped++; }
                if (skipped < offset && refs.hasNext()) throw new IllegalStateException("xref cursor scan exceeded query deadline; use a scoped script");
                while (refs.hasNext() && rows.size() < limit && System.nanoTime() < deadline) {
                    var ref = refs.next();
                    JsonObject row = new JsonObject();
                    row.addProperty("from", "0x" + ref.getFromAddress());
                    row.addProperty("to", "0x" + ref.getToAddress());
                    row.addProperty("type", ref.getReferenceType().toString());
                    rows.add(row);
                }
                out.add("references", rows);
                out.addProperty("truncated", refs.hasNext());
                if (refs.hasNext()) out.addProperty("next_cursor", "0x" + Long.toHexString(skipped + rows.size()));
            } else {
                Function f = fm.getFunctionContaining(addr);
                if (f == null) throw new IllegalArgumentException("no analysed function contains " + addr);
                out.add("function", function(f));
                if (action.equals("decompile")) {
                    if (decompiler == null) decompiler = borrow(currentProgram);
                    var result = decompiler.decompileFunction(f, seconds, monitor);
                    if (!result.decompileCompleted()) throw new IllegalStateException("decompile refused: " + result.getErrorMessage());
                    String c = result.getDecompiledFunction().getC();
                    int maximum = number(options(req), "max_characters", 32000);
                    out.addProperty("c", c.substring(0, Math.min(c.length(), maximum)));
                    out.addProperty("truncated", c.length() > maximum);
                    out.addProperty("max_characters", maximum);
                    out.addProperty("total_characters", c.length());
                }
            }
        }
        out.addProperty("ok", true);
        return out;
    }

    // One request per run: args[0] is the request as JSON, or @<file> holding it.
    // The answer is printed as a single JSON line; the engine returns it as `output`.
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("RusticQuery takes one argument: a JSON request or @file");
        String body = args[0].startsWith("@") ? Files.readString(Path.of(args[0].substring(1)), StandardCharsets.UTF_8) : args[0];
        JsonObject req;
        try (JsonReader reader = new JsonReader(new StringReader(body))) {
            reader.setStrictness(Strictness.STRICT);
            JsonElement element = JsonParser.parseReader(reader);
            if (!element.isJsonObject() || reader.peek() != JsonToken.END_DOCUMENT) throw new IllegalArgumentException("request must be one JSON object");
            req = element.getAsJsonObject();
        }
        if (currentProgram == null) throw new IllegalArgumentException("RusticQuery needs an open program");
        JsonObject response;
        boolean healthy = true;
        try {
            if (!GhidraProgramUtilities.isAnalyzed(currentProgram)) throw new IllegalStateException("program has not been analysed; prepare it first");
            response = query(req);
        } catch (Exception error) {
            response = queryError(text(req, "id"), error);
            healthy = response.get("recoverable").getAsBoolean();
        } finally {
            if (decompiler != null) { giveBack(currentProgram, decompiler, healthy); decompiler = null; }
        }
        println(json.toJson(response));
    }
}
