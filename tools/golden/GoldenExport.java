// GoldenExport: decompile every function of the current program with EXPLICIT decompiler
// options and write one JSON line per function (see docs/golden-harness.md).
//
// This is a plain GhidraScript with no Hydra-specific API, so the same source runs under
// stock Ghidra (analyzeHeadless -process <program> -noanalysis -readOnly -postScript) and
// under Hydra Engine's `script` command. That is the point: the golden harness compares
// decompiler output across engines with one identical driver and one identical set of
// decompiler options (the options are fixed below and dumped in the header).
//
// Arguments: <out.jsonl> [timeout_s=120] [entries.txt|-] [options=fixed|program]
//   out.jsonl    written as <out>.part and renamed when complete
//   timeout_s    per-function decompile timeout
//   entries.txt  optional: only these entry points (one hex address per line, "0x" optional)
//   options      fixed (default): DecompileOptions set explicitly below, nothing read from the program
//                program: the same, then grabFromProgram(currentProgram), as the Ghidra window does
//
// The C text of each function is written to the file as "c"; the file is local data and
// is never committed (it is derived from the analysed binary).
//@category Hydra.Golden
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.io.BufferedWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeMap;

public class GoldenExport extends GhidraScript {
    private final Gson json = new Gson();

    private static String sha256(String text) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        StringBuilder out = new StringBuilder();
        for (byte b : digest.digest(text.getBytes(StandardCharsets.UTF_8))) out.append(String.format("%02x", b));
        return out.toString();
    }

    /** The explicit options. Everything not set here keeps the version's own default, and is dumped. */
    private DecompileOptions explicitOptions(int timeoutSeconds, boolean fromProgram) {
        DecompileOptions options = new DecompileOptions();   // deliberately no grabFromProgram
        options.setEliminateUnreachable(true);
        options.setSimplifyDoublePrecision(true);
        options.setRespectReadOnly(true);
        options.setIgnoreUnimplemented(false);
        options.setInferConstantPointers(true);
        options.setAnalyzeForLoops(true);
        options.setPredicate(true);
        options.setMaxInstructions(100000);
        options.setMaxPayloadMBytes(50);
        options.setDefaultTimeout(timeoutSeconds);
        if (fromProgram) options.grabFromProgram(currentProgram);
        return options;
    }

    private JsonObject describe(DecompileOptions options) {
        TreeMap<String, String> values = new TreeMap<>();
        for (Field field : DecompileOptions.class.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers())) continue;
            Class<?> type = field.getType();
            String name = type.getName();
            if (name.startsWith("java.awt") || name.contains("NameTransformer")) continue;
            try {
                field.setAccessible(true);
                values.put(field.getName(), String.valueOf(field.get(options)));
            }
            catch (Exception error) {
                values.put(field.getName(), "unreadable: " + error.getClass().getSimpleName());
            }
        }
        JsonObject out = new JsonObject();
        for (var entry : values.entrySet()) out.addProperty(entry.getKey(), entry.getValue());
        return out;
    }

    private static String entryText(Address address) {
        return "0x" + address;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException("GoldenExport takes <out.jsonl> [timeout_s] [entries.txt]");
        if (currentProgram == null) throw new IllegalArgumentException("GoldenExport needs an open program");
        Path target = Path.of(args[0]);
        int timeout = args.length > 1 ? Integer.parseInt(args[1]) : 120;
        Set<String> only = null;
        if (args.length > 2 && !args[2].isEmpty() && !args[2].equals("-")) {
            only = new HashSet<>();
            for (String line : Files.readAllLines(Path.of(args[2]), StandardCharsets.UTF_8)) {
                String text = line.trim().toLowerCase().replaceFirst("^0x", "").replaceFirst("^0+(?=.)", "");
                if (!text.isEmpty()) only.add(text);
            }
        }
        Path part = target.resolveSibling(target.getFileName() + ".part");
        Files.createDirectories(part.toAbsolutePath().getParent());
        FunctionManager manager = currentProgram.getFunctionManager();
        String mode = args.length > 3 && !args[3].isEmpty() ? args[3] : "fixed";
        if (!mode.equals("fixed") && !mode.equals("program")) throw new IllegalArgumentException("options must be fixed or program");
        DecompileOptions options = explicitOptions(timeout, mode.equals("program"));
        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(options);
        if (!decompiler.openProgram(currentProgram)) {
            String message = decompiler.getLastMessage();
            decompiler.dispose();
            throw new IllegalStateException("decompiler would not open the program: " + message);
        }
        long started = System.nanoTime();
        int internal = 0, thunks = 0, written = 0, failed = 0;
        try (BufferedWriter writer = Files.newBufferedWriter(part, StandardCharsets.UTF_8)) {
            FunctionIterator count = manager.getFunctions(true);
            while (count.hasNext()) { Function f = count.next(); internal++; if (f.isThunk()) thunks++; }
            JsonObject header = new JsonObject();
            header.addProperty("type", "header");
            header.addProperty("tool", "GoldenExport.java");
            header.addProperty("path", "explicit");
            header.addProperty("application_version", Application.getApplicationVersion());
            header.addProperty("application_release", Application.getApplicationReleaseName());
            header.addProperty("program", currentProgram.getName());
            header.addProperty("program_sha256", currentProgram.getExecutableSHA256());
            header.addProperty("image_base", "0x" + currentProgram.getImageBase());
            header.addProperty("language", currentProgram.getLanguageID().toString());
            header.addProperty("compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
            header.addProperty("function_count_total", manager.getFunctionCount());
            header.addProperty("function_count_internal", internal);
            header.addProperty("function_count_thunks", thunks);
            header.addProperty("timeout_s", timeout);
            header.addProperty("options_mode", mode);
            header.addProperty("only_listed", only == null ? -1 : only.size());
            header.add("options", describe(options));
            writer.write(json.toJson(header)); writer.write('\n');
            monitor.initialize(internal);
            FunctionIterator functions = manager.getFunctions(true);
            while (functions.hasNext()) {
                monitor.checkCancelled();
                Function f = functions.next();
                String entry = entryText(f.getEntryPoint());
                if (only != null && !only.contains(entry.substring(2).toLowerCase().replaceFirst("^0+(?=.)", ""))) continue;
                JsonObject row = new JsonObject();
                row.addProperty("type", "function");
                row.addProperty("entry", entry);
                row.addProperty("name", f.getName());
                row.addProperty("size", f.getBody().getNumAddresses());
                row.addProperty("thunk", f.isThunk());
                long begin = System.nanoTime();
                String status;
                String error = null;
                String text = null;
                try {
                    DecompileResults result = decompiler.decompileFunction(f, timeout, monitor);
                    if (result.decompileCompleted() && result.getDecompiledFunction() != null && result.getDecompiledFunction().getC() != null) {
                        status = "ok";
                        text = result.getDecompiledFunction().getC();
                    }
                    else {
                        status = result.isTimedOut() ? "timeout" : "failed";
                        error = String.valueOf(result.getErrorMessage());
                    }
                }
                catch (Exception caught) {
                    if (caught instanceof ghidra.util.exception.CancelledException) throw caught;
                    status = "failed";
                    error = caught.toString();
                }
                double millis = (System.nanoTime() - begin) / 1_000_000.0;
                row.addProperty("status", status);
                row.addProperty("ms", Math.round(millis * 1000.0) / 1000.0);
                if (error != null) row.addProperty("error", error.length() > 2000 ? error.substring(0, 2000) : error);
                if (text != null) {
                    row.addProperty("c_sha256", sha256(text));
                    row.addProperty("c", text);
                }
                else failed++;
                writer.write(json.toJson(row)); writer.write('\n');
                written++;
                if (written % 200 == 0) { writer.flush(); monitor.setProgress(written); monitor.setMessage("decompiled " + written); }
            }
            JsonObject footer = new JsonObject();
            footer.addProperty("type", "footer");
            footer.addProperty("rows", written);
            footer.addProperty("failed", failed);
            footer.addProperty("seconds", Math.round((System.nanoTime() - started) / 1e6) / 1000.0);
            writer.write(json.toJson(footer)); writer.write('\n');
        }
        finally {
            decompiler.dispose();
        }
        Files.move(part, target, StandardCopyOption.REPLACE_EXISTING);
        println(json.toJson(java.util.Map.of("golden_export", target.toString(), "rows", written, "failed", failed)));
    }
}
