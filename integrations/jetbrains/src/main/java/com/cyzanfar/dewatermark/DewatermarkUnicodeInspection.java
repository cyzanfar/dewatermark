package com.cyzanfar.dewatermark;

import com.intellij.codeInspection.LocalInspectionTool;
import com.intellij.codeInspection.LocalQuickFix;
import com.intellij.codeInspection.ProblemDescriptor;
import com.intellij.codeInspection.ProblemsHolder;
import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.TextRange;
import com.intellij.psi.PsiDocumentManager;
import com.intellij.psi.PsiElementVisitor;
import com.intellij.psi.PsiFile;
import com.intellij.openapi.vfs.VirtualFile;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.nio.file.Path;

public final class DewatermarkUnicodeInspection extends LocalInspectionTool {
    @Override
    public @NotNull PsiElementVisitor buildVisitor(
            @NotNull ProblemsHolder holder, boolean isOnTheFly) {
        return new PsiElementVisitor() {
            @Override
            public void visitFile(@NotNull PsiFile file) {
                Document document = PsiDocumentManager.getInstance(file.getProject()).getDocument(file);
                if (document == null || document.getTextLength() > DewatermarkCli.MAX_INPUT_BYTES) return;
                try {
                    for (DewatermarkCli.Finding finding :
                            DewatermarkCli.scan(document.getText(), sourcePath(file))) {
                        TextRange range = rangeFor(document, finding.line(), finding.column());
                        if (range == null) continue;
                        holder.registerProblem(
                                file,
                                range,
                                finding.message() + " (" + finding.codepoint() + ")",
                                new SafeCleanupFix());
                    }
                } catch (IOException | RuntimeException ignored) {
                    // Diagnostics disappear on a bounded local process failure; source and
                    // exception details are deliberately not logged.
                }
            }
        };
    }

    private static Path sourcePath(PsiFile file) {
        VirtualFile virtualFile = file.getVirtualFile();
        if (virtualFile == null) return null;
        try {
            return virtualFile.toNioPath();
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static TextRange rangeFor(Document document, int oneBasedLine, int oneBasedColumn) {
        int line = oneBasedLine - 1;
        if (line < 0 || line >= document.getLineCount()) return null;
        int start = document.getLineStartOffset(line);
        int end = document.getLineEndOffset(line);
        String value = document.getText(TextRange.create(start, end));
        int codepoint = oneBasedColumn - 1;
        if (codepoint < 0 || codepoint >= value.codePointCount(0, value.length())) return null;
        int offset = start + value.offsetByCodePoints(0, codepoint);
        int width = Character.charCount(document.getText().codePointAt(offset));
        return TextRange.create(offset, Math.min(document.getTextLength(), offset + width));
    }

    private static final class SafeCleanupFix implements LocalQuickFix {
        @Override
        public @NotNull String getFamilyName() {
            return "Apply dewatermark safe Unicode cleanup";
        }

        @Override
        public void applyFix(@NotNull Project project, @NotNull ProblemDescriptor descriptor) {
            PsiFile file = descriptor.getPsiElement().getContainingFile();
            Document document = PsiDocumentManager.getInstance(project).getDocument(file);
            if (document == null) return;
            String source = document.getText();
            long modificationStamp = document.getModificationStamp();
            try {
                String cleaned = DewatermarkCli.sanitize(source, sourcePath(file));
                if (!cleaned.equals(source) && document.getModificationStamp() == modificationStamp) {
                    WriteCommandAction.runWriteCommandAction(project, () -> document.setText(cleaned));
                }
            } catch (IOException | RuntimeException ignored) {
                // Fail closed: the editor buffer remains unchanged.
            }
        }
    }
}
