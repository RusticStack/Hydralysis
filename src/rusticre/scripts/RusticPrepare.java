// Verify the one explicit initial import/analysis before registering its project.
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.util.GhidraProgramUtilities;
import com.google.gson.JsonObject;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

public class RusticPrepare extends HeadlessScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (analysisTimeoutOccurred()) throw new IllegalStateException("initial analysis timed out");
        if (!GhidraProgramUtilities.isAnalyzed(currentProgram)) throw new IllegalStateException("initial analysis did not complete");
        if (!args[0].equalsIgnoreCase(currentProgram.getExecutableSHA256())) throw new IllegalStateException("imported SHA256 differs from source snapshot");
        JsonObject result = new JsonObject();
        result.addProperty("analysed", true);
        result.addProperty("sha256", currentProgram.getExecutableSHA256());
        result.addProperty("program", currentProgram.getName());
        result.addProperty("image_base", "0x" + currentProgram.getImageBase());
        result.addProperty("function_count", currentProgram.getFunctionManager().getFunctionCount());
        Path output = Path.of(args[1]);
        Path temporary = output.resolveSibling(output.getFileName() + ".tmp");
        Files.writeString(temporary, result.toString(), StandardCharsets.UTF_8);
        Files.move(temporary, output, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        println("RUSTICRE_ANALYSIS_VERIFIED " + result.toString());
    }
}
