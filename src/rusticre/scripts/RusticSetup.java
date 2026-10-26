// Creates an empty project for a first import. The engine has no create command;
// this runs with no program open. args: <project directory> <project name>.
import ghidra.app.script.GhidraScript;
import ghidra.base.project.GhidraProject;
import java.io.File;

public class RusticSetup extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("RusticSetup takes <project directory> <project name>");
        File directory = new File(args[0]);
        if (new File(directory, args[1] + ".gpr").exists()) throw new IllegalArgumentException("project already exists: " + args[0]);
        if (!directory.isDirectory() && !directory.mkdirs()) throw new IllegalStateException("cannot create " + args[0]);
        GhidraProject.createProject(args[0], args[1], false).close();
        println("{\"created\":true}");
    }
}
