// Address-based, bounded queries on a program opened by -process -noanalysis -readOnly.
// This script never imports, analyses, saves or mutates the program.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.util.GhidraProgramUtilities;
import com.google.gson.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public class RusticQuery extends GhidraScript {
    private final Gson json = new Gson();
    private DecompInterface decompiler;

    private void write(Path path, JsonObject body) throws Exception {
        Path temp = path.resolveSibling(path.getFileName() + ".tmp");
        Files.writeString(temp, json.toJson(body), StandardCharsets.UTF_8);
        Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private String text(JsonObject req, String key) {
        return req.has(key) ? req.get(key).getAsString() : "";
    }

    private Address address(String value) {
        return toAddr(value.startsWith("0x") ? value.substring(2) : value);
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
        while (ranges.hasNext() && body.size() < 64) body.add(ranges.next().toString());
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
                    if (decompiler == null) {
                        decompiler = new DecompInterface();
                        if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
                    }
                    var result = decompiler.decompileFunction(f, seconds, monitor);
                    if (!result.decompileCompleted()) throw new IllegalStateException("decompile refused: " + result.getErrorMessage());
                    String c = result.getDecompiledFunction().getC();
                    out.addProperty("c", c.substring(0, Math.min(c.length(), 32000)));
                    out.addProperty("truncated", c.length() > 32000);
                    out.addProperty("total_characters", c.length());
                }
            }
        }
        out.addProperty("ok", true);
        return out;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Path directory = Path.of(args[0]);
        JsonObject ready = new JsonObject();
        ready.addProperty("pid", ProcessHandle.current().pid());
        ready.addProperty("started_ms", ProcessHandle.current().info().startInstant().get().toEpochMilli());
        ready.addProperty("program", currentProgram.getName());
        ready.addProperty("sha256", currentProgram.getExecutableSHA256());
        try {
            if (!GhidraProgramUtilities.isAnalyzed(currentProgram)) throw new IllegalStateException("program has not been analysed; prepare it separately first");
            if (!args[1].equalsIgnoreCase(currentProgram.getExecutableSHA256())) throw new IllegalStateException("project SHA256 differs from target binary; stale or packed analysis project");
            ready.addProperty("ok", true);
        } catch (Exception e) {
            ready.addProperty("ok", false);
            ready.addProperty("error", e.toString());
            write(directory.resolve("ready.json"), ready);
            return;
        }
        write(directory.resolve("ready.json"), ready);
        long idle = TimeUnit.SECONDS.toNanos(Integer.parseInt(args[2]));
        long touched = System.nanoTime();
        String previous = "";
        try {
            while (!monitor.isCancelled() && System.nanoTime() - touched < idle) {
                Path request = directory.resolve("request.json");
                if (!Files.exists(request)) { Thread.sleep(50); continue; }
                JsonObject req = JsonParser.parseString(Files.readString(request)).getAsJsonObject();
                String id = text(req, "id");
                if (id.equals(previous)) { Thread.sleep(50); continue; }
                previous = id;
                touched = System.nanoTime();
                JsonObject response;
                try { response = query(req); }
                catch (Exception e) {
                    response = new JsonObject();
                    response.addProperty("id", id);
                    response.addProperty("ok", false);
                    response.addProperty("error", e.toString());
                    if (decompiler != null) { decompiler.dispose(); decompiler = null; }
                }
                write(directory.resolve("response.json"), response);
                touched = System.nanoTime();
            }
        } finally {
            if (decompiler != null) decompiler.dispose();
        }
    }
}
