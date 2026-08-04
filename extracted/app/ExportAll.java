import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.data.*;
import java.io.*;
import java.util.*;

public class ExportAll extends GhidraScript {

    @Override
    public void run() throws Exception {
        if (getScriptArgs().length < 1) {
            println("Usage: ExportAll.java <output_dir>");
            return;
        }
        File outDir = new File(getScriptArgs()[0]);
        outDir.mkdirs();

        Program prog = currentProgram;
        String base = prog.getName().replaceAll("[^A-Za-z0-9_.\\-]", "_");

        File cFile   = new File(outDir, base + "_decompiled.c");
        File fnFile  = new File(outDir, base + "_functions.txt");
        File xrFile  = new File(outDir, base + "_string_xrefs.txt");
        File asmFile = new File(outDir, base + "_proxy_functions.asm");

        PrintWriter cw = new PrintWriter(new FileWriter(cFile));
        PrintWriter fw = new PrintWriter(new FileWriter(fnFile));
        PrintWriter xw = new PrintWriter(new FileWriter(xrFile));
        PrintWriter aw = new PrintWriter(new FileWriter(asmFile));

        DecompInterface decomp = new DecompInterface();
        decomp.setSimplificationStyle("decompile");
        decomp.openProgram(prog);

        Listing listing = prog.getListing();
        FunctionManager fm = prog.getFunctionManager();

        // 1) decompile every function to one big .c
        FunctionIterator fns = fm.getFunctions(true);
        int total = 0;
        Set<Function> proxyFuncs = new TreeSet<>(Comparator.comparing(f -> f.getEntryPoint().toString()));
        while (fns.hasNext() && !monitor.isCancelled()) {
            Function fn = fns.next();
            total++;
            Address addr = fn.getEntryPoint();
            fw.println(String.format("%-60s %s", fn.getName(), addr));
            DecompileResults res = decomp.decompileFunction(fn, 120, monitor);
            if (res.decompileCompleted()) {
                cw.println("/* ============ " + fn.getName() + " @ " + addr + " ============ */");
                cw.println(res.getDecompiledFunction().getC());
            } else {
                cw.println("/* DECOMPILE FAILED: " + fn.getName() + " @ " + addr + " */");
            }
        }
        cw.flush();

        // 2) find defined strings matching keywords, and which functions reference them
        String[] keywords = { "Proxy", "Socks", "HTTP_", "HTTPS_", "FTP_", "Internet Settings",
                              "ProxyServer", "ProxyEnable", "IsActive", "Software\\", "NeatDM" };
        DataIterator dit = listing.getDefinedData(true);
        long strCount = 0;
        while (dit.hasNext() && !monitor.isCancelled()) {
            Data d = dit.next();
            DataType dt = d.getDataType();
            String val = null;
            try {
                if (dt instanceof UnicodeDataType) val = (String) d.getValue();
                else if (dt instanceof StringDataType) val = (String) d.getValue();
            } catch (Exception e) { val = null; }
            if (val == null) continue;
            String low = val.toLowerCase();
            boolean hit = false;
            for (String k : keywords) {
                if (low.contains(k.toLowerCase())) { hit = true; break; }
            }
            if (!hit) continue;
            strCount++;
            Address a = d.getAddress();
            ReferenceIterator rit = prog.getReferenceManager().getReferencesTo(a);
            List<Function> funcs = new ArrayList<>();
            while (rit.hasNext()) {
                Reference ref = rit.next();
                Function fn = fm.getFunctionContaining(ref.getFromAddress());
                if (fn != null && !funcs.contains(fn)) funcs.add(fn);
            }
            xw.println("STRING @ " + a + " [" + val.replaceAll("\\s+", " ") + "]");
            for (Function fn : funcs) {
                xw.println("    <- " + fn.getName() + " @ " + fn.getEntryPoint());
                proxyFuncs.add(fn);
            }
        }
        xw.flush();

        // 3) full disassembly of every function that touched a keyword string
        for (Function fn : proxyFuncs) {
            aw.println("; ============ " + fn.getName() + " @ " + fn.getEntryPoint() + " ============");
            InstructionIterator iit = listing.getInstructions(fn.getBody(), true);
            while (iit.hasNext() && !monitor.isCancelled()) {
                Instruction ins = iit.next();
                aw.println(ins.getAddress() + "  " + ins);
            }
            aw.println();
        }
        aw.flush();

        println("done: functions=" + total + ", keywordStrings=" + strCount + ", proxyFuncs=" + proxyFuncs.size());
        cw.close(); fw.close(); xw.close(); aw.close();
        decomp.dispose();
    }
}
