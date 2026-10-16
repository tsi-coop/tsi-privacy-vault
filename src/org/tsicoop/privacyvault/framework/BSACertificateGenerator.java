package org.tsicoop.privacyvault.framework;

import java.io.OutputStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import java.util.ArrayList;
import java.util.List;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

public class BSACertificateGenerator {

    public void streamSection63Certificate(JSONObject data, OutputStream out) throws Exception {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage();
            document.addPage(page);

            try (PDPageContentStream contentStream = new PDPageContentStream(document, page)) {
                // Setup Fonts
                var fontBold = new org.apache.pdfbox.pdmodel.font.PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD);
                var fontRegular = new org.apache.pdfbox.pdmodel.font.PDType1Font(Standard14Fonts.FontName.HELVETICA);

                float startX = 50;
                float startY = 750;
                float leading = 15;

                // 1. Title: Statutory Reference
                contentStream.beginText();
                contentStream.setFont(fontBold, 14);
                contentStream.newLineAtOffset(150, startY);
                contentStream.showText("CERTIFICATE");
                contentStream.endText();

                startY -= leading;
                contentStream.beginText();
                contentStream.setFont(fontBold, 10);
                contentStream.newLineAtOffset(100, startY);
                contentStream.showText("[Section 63(4)(c) of Bharatiya Sakshya Adhiniyam, 2023]");
                contentStream.endText();

                // 2. PART A: User Declaration
                startY -= (leading * 3);
                contentStream.beginText();
                contentStream.setFont(fontBold, 12);
                contentStream.newLineAtOffset(startX, startY);
                contentStream.showText("PART A: (To be filled by the Party)");
                contentStream.endText();

                contentStream.beginText();
                contentStream.setFont(fontRegular, 10);
                contentStream.newLineAtOffset(startX, startY - leading);
                contentStream.showText("I produced the digital record from the following device:");
                contentStream.newLineAtOffset(0, -leading);
                contentStream.showText("Make & Model: " + data.get("machine_model"));
                contentStream.newLineAtOffset(0, -leading);
                contentStream.showText("MAC/Cloud ID: " + data.get("mac_address"));
                contentStream.newLineAtOffset(0, -leading);
                contentStream.showText("System Status: " + data.get("health_status")); // Sec 63(2)(c)
                contentStream.newLineAtOffset(0, -leading);
                contentStream.showText("HASH (SHA256): " + data.get("sha256_hash")); // Part B Requirement
                contentStream.endText();

                // 3. PART B: Expert Validation
                startY -= (leading * 10);
                contentStream.beginText();
                contentStream.setFont(fontBold, 12);
                contentStream.newLineAtOffset(startX, startY);
                contentStream.showText("PART B: (To be filled by the Expert)");
                contentStream.endText();

                contentStream.beginText();
                contentStream.setFont(fontRegular, 10);
                contentStream.newLineAtOffset(startX, startY - leading);
                contentStream.showText("I have verified the electronic record from the device listed above.");
                contentStream.newLineAtOffset(0, -leading);
                contentStream.showText("Verified Hash: " + data.get("sha256_hash"));
                contentStream.newLineAtOffset(0, -leading);
                contentStream.showText("Software Source: " + data.get("software_version"));
                contentStream.newLineAtOffset(0, -leading);
                contentStream.showText("Timestamp (IST): " + data.get("anchor_time"));
                contentStream.endText();

                // 4. Audit log integrity (system record). The head lets anyone holding this
                // certificate check later that the vault's audit log has not been rewritten.
                startY -= (leading * 8);
                contentStream.beginText();
                contentStream.setFont(fontBold, 12);
                contentStream.newLineAtOffset(startX, startY);
                contentStream.showText("AUDIT LOG INTEGRITY (system record)");
                contentStream.endText();

                contentStream.beginText();
                contentStream.setFont(fontRegular, 9);
                contentStream.newLineAtOffset(startX, startY - leading);
                contentStream.showText("Event: sequence " + data.get("chain_event_seq"));
                contentStream.newLineAtOffset(0, -leading);
                contentStream.showText("Event hash: " + data.get("chain_event_hash"));
                contentStream.newLineAtOffset(0, -leading);
                contentStream.showText("Log head at issue: sequence " + data.get("chain_head_seq"));
                contentStream.newLineAtOffset(0, -leading);
                contentStream.showText("Head hash: " + data.get("chain_head_hash"));
                contentStream.newLineAtOffset(0, -leading);
                contentStream.showText("Chain verified from the event to the head at: " + data.get("chain_verified_at"));
                contentStream.endText();
            }

            document.save(out); // Stream directly to HTTP response
        }
    }

    // ------------------------------------------------------------------ custody certificate

    /** Events listed per record and kind before the rest are summarised by the chain range. */
    private static final int MAX_LISTED_PER_KIND = 50;

    /**
     * Custody certificate for a data principal (or one record): the lifecycle of every record,
     * with its STORE, FETCH, SEARCH and ERASE events, the erasure and hold position, the audit
     * chain verification and a digest over the whole manifest. Data comes from
     * {@link CustodyService#certificate}.
     */
    public void streamCustodyCertificate(JSONObject c, OutputStream out) throws Exception {
        try (PDDocument document = new PDDocument()) {
            Pdf pdf = new Pdf(document);
            JSONObject subject = (JSONObject) c.get("subject");
            JSONObject summary = (JSONObject) c.get("summary");
            JSONObject chain = (JSONObject) c.get("chain");
            boolean principal = "PRINCIPAL".equals(subject.get("mode"));

            pdf.center("CERTIFICATE OF CUSTODY", true, 14);
            pdf.center("[Section 63(4)(c) of Bharatiya Sakshya Adhiniyam, 2023]", true, 10);
            pdf.gap(1);

            pdf.heading("PART A: (To be filled by the Party)");
            pdf.line("I produced the digital records described below from the following system:", false, 10);
            pdf.line("Make & Model / Cloud ID: " + c.get("machine_id"), false, 10);
            pdf.line("System Status: ACTIVE_SECURE_VAULT", false, 10);
            pdf.line("Software Source: " + c.get("software_version"), false, 10);
            pdf.line("Generated (UTC): " + c.get("generated_at"), false, 10);
            pdf.gap(1);

            pdf.heading("SUBJECT");
            if (principal) {
                pdf.line("Principal ID: " + subject.get("principal_id"), false, 10);
            } else {
                pdf.line("Single record, stored without a principal ID.", false, 10);
            }
            pdf.line("Records: " + summary.get("records") + " (held " + summary.get("held") + ", erased " + summary.get("erased") + ")", false, 10);
            pdf.line("Events: store " + summary.get("store_events") + ", fetch " + summary.get("fetch_events")
                    + ", search " + summary.get("search_events") + ", erase " + summary.get("erase_events"), false, 10);
            pdf.gap(1);

            pdf.heading("CUSTODY LIFECYCLE BY RECORD");
            int n = 0;
            for (Object o : (JSONArray) c.get("records")) {
                JSONObject r = (JSONObject) o;
                n++;
                pdf.line("Record " + n + ": " + r.get("reference_key"), true, 10);
                pdf.line("Type: " + r.get("flavor") + " / " + r.get("entity_code") + "    Stored (UTC): " + r.get("created_at"), false, 9, 12);
                if (r.get("erased_at") != null) {
                    pdf.line("Status: ERASED (UTC " + r.get("erased_at") + "). The value hash and key were destroyed with it.", false, 9, 12);
                } else {
                    pdf.line("Status: HELD" + (r.get("retain_until") != null ? ", retained until (UTC) " + r.get("retain_until") : ""), false, 9, 12);
                    pdf.line("HASH (SHA256): " + r.get("sha256"), false, 8, 12);
                }
                java.util.Map<String, Integer> listed = new java.util.HashMap<>();
                java.util.Map<String, Integer> total = new java.util.HashMap<>();
                JSONArray events = (JSONArray) r.get("events");
                for (Object eo : events) total.merge((String) ((JSONObject) eo).get("kind"), 1, Integer::sum);
                int omitted = 0;
                Long firstOmitted = null, lastOmitted = null;
                for (Object eo : events) {
                    JSONObject e = (JSONObject) eo;
                    String kind = (String) e.get("kind");
                    int seen = listed.merge(kind, 1, Integer::sum);
                    // List the newest events per kind; the earlier ones are covered by the digest.
                    if (total.get(kind) - seen >= MAX_LISTED_PER_KIND) {
                        omitted++;
                        Number seq = (Number) e.get("chain_seq");
                        if (seq != null) {
                            if (firstOmitted == null) firstOmitted = seq.longValue();
                            lastOmitted = seq.longValue();
                        }
                        continue;
                    }
                    String by = String.valueOf(e.get("who"));
                    String seq = e.get("chain_seq") == null ? "-" : String.valueOf(e.get("chain_seq"));
                    pdf.line(e.get("at") + "  " + kind + "  " + e.get("outcome") + "  " + by + "  seq " + seq
                            + ("DENIED".equals(e.get("outcome")) && e.get("reason") != null ? "  (" + e.get("reason") + ")" : ""), false, 8, 12);
                }
                if (omitted > 0) {
                    pdf.line(omitted + " earlier events are not listed here. They are covered by the manifest digest"
                            + (firstOmitted != null ? " and audit sequences " + firstOmitted + " to " + lastOmitted : "") + ".", false, 8, 12);
                }
                pdf.gap(0.6f);
            }

            JSONObject er = (JSONObject) subject.get("erasure");
            JSONArray holds = (JSONArray) subject.get("holds");
            JSONArray erEvents = (JSONArray) subject.get("erasure_events");
            if (principal) {
                pdf.heading("ERASURE AND HOLDS");
                if (er == null) {
                    pdf.line("No erasure has been requested for this principal.", false, 9);
                } else {
                    pdf.line("Erasure state: " + er.get("state") + ", requested by " + er.get("requested_by") + " at (UTC) " + er.get("requested_at"), false, 9);
                    pdf.line("Records destroyed: " + er.get("records_destroyed") + "    Records retained: " + er.get("records_retained")
                            + (er.get("shredded_at") != null ? "    Completed (UTC): " + er.get("shredded_at") : "")
                            + (er.get("next_due") != null ? "    Next due (UTC): " + er.get("next_due") : ""), false, 9);
                }
                for (Object eo : erEvents) {
                    JSONObject e = (JSONObject) eo;
                    pdf.line(e.get("at") + "  " + e.get("outcome") + "  " + e.get("who") + "  seq " + e.get("chain_seq")
                            + "  " + e.get("operation"), false, 8, 12);
                }
                if (holds.isEmpty()) {
                    pdf.line("Legal holds: none recorded.", false, 9);
                } else {
                    for (Object ho : holds) {
                        JSONObject h = (JSONObject) ho;
                        pdf.line("Legal hold #" + h.get("hold_id") + ": placed " + h.get("placed_at") + " by " + h.get("placed_by")
                                + (h.get("case_ref") != null ? ", case " + h.get("case_ref") : "")
                                + (h.get("released_at") != null ? ", released " + h.get("released_at") : ", OPEN"), false, 9);
                    }
                }
                pdf.gap(1);
            }

            pdf.heading("AUDIT LOG INTEGRITY (system record)");
            if (Boolean.TRUE.equals(chain.get("verified"))) {
                pdf.line("Chain verified from sequence " + chain.get("from_seq") + " to the head at (UTC): " + chain.get("verified_at"), false, 9);
                pdf.line("Log head at issue: sequence " + chain.get("head_seq"), false, 9);
                pdf.line("Head hash: " + chain.get("head_hash"), false, 8);
            } else {
                pdf.line(String.valueOf(chain.get("note")), false, 9);
            }
            pdf.line("Manifest digest (SHA256): " + c.get("manifest_sha256"), true, 8);
            pdf.line("The digest covers every record and event above, including those not listed, and the audit row hash of each event.", false, 8);
            pdf.gap(1);

            pdf.heading("PART B: (To be filled by the Expert)");
            pdf.line("I have verified the electronic records from the system listed above.", false, 10);
            pdf.line("Verified manifest digest: " + c.get("manifest_sha256"), false, 8);
            pdf.line("Software Source: " + c.get("software_version"), false, 10);
            pdf.gap(2);
            pdf.line("Signature: ______________________      Name: ______________________      Date: ____________", false, 9);

            pdf.close();
            document.save(out);
        }
    }

    /** Minimal top-down text writer: wraps long lines and starts a new page when one is full. */
    private static class Pdf {
        private final PDDocument doc;
        private PDPage page;
        private PDPageContentStream cs;
        private float y;
        private static final float TOP = 780, BOTTOM = 50, LEFT = 50, WIDTH = 500;
        private final org.apache.pdfbox.pdmodel.font.PDType1Font bold =
                new org.apache.pdfbox.pdmodel.font.PDType1Font(Standard14Fonts.FontName.HELVETICA_BOLD);
        private final org.apache.pdfbox.pdmodel.font.PDType1Font regular =
                new org.apache.pdfbox.pdmodel.font.PDType1Font(Standard14Fonts.FontName.HELVETICA);

        Pdf(PDDocument doc) throws java.io.IOException {
            this.doc = doc;
            newPage();
        }

        private void newPage() throws java.io.IOException {
            if (cs != null) cs.close();
            page = new PDPage();
            doc.addPage(page);
            cs = new PDPageContentStream(doc, page);
            y = TOP;
        }

        void close() throws java.io.IOException {
            if (cs != null) cs.close();
            cs = null;
        }

        void gap(float lines) throws java.io.IOException {
            y -= 12 * lines;
            if (y < BOTTOM) newPage();
        }

        void heading(String text) throws java.io.IOException {
            line(text, true, 11);
        }

        void center(String text, boolean b, float size) throws java.io.IOException {
            var f = b ? bold : regular;
            float w = f.getStringWidth(clean(text)) / 1000 * size;
            write(clean(text), f, size, LEFT + Math.max(0, (WIDTH - w) / 2), size + 4);
        }

        void line(String text, boolean b, float size) throws java.io.IOException {
            line(text, b, size, 0);
        }

        void line(String text, boolean b, float size, float indent) throws java.io.IOException {
            var f = b ? bold : regular;
            float max = WIDTH - indent;
            for (String part : wrap(clean(text), f, size, max)) {
                write(part, f, size, LEFT + indent, size + 3);
            }
        }

        private void write(String text, org.apache.pdfbox.pdmodel.font.PDType1Font f, float size, float x, float leading)
                throws java.io.IOException {
            if (y - leading < BOTTOM) newPage();
            y -= leading;
            cs.beginText();
            cs.setFont(f, size);
            cs.newLineAtOffset(x, y);
            cs.showText(text);
            cs.endText();
        }

        /** Breaks on spaces, and hard-breaks tokens (hashes, uuids) that are wider than the line. */
        private List<String> wrap(String text, org.apache.pdfbox.pdmodel.font.PDType1Font f, float size, float max)
                throws java.io.IOException {
            List<String> lines = new ArrayList<>();
            StringBuilder cur = new StringBuilder();
            for (String word : text.split(" ", -1)) {
                String trial = cur.length() == 0 ? word : cur + " " + word;
                if (f.getStringWidth(trial) / 1000 * size <= max) {
                    cur = new StringBuilder(trial);
                    continue;
                }
                if (cur.length() > 0) lines.add(cur.toString());
                cur = new StringBuilder();
                String rest = word;
                while (f.getStringWidth(rest) / 1000 * size > max && rest.length() > 1) {
                    int cut = rest.length();
                    while (cut > 1 && f.getStringWidth(rest.substring(0, cut)) / 1000 * size > max) cut--;
                    lines.add(rest.substring(0, cut));
                    rest = rest.substring(cut);
                }
                cur.append(rest);
            }
            if (cur.length() > 0 || lines.isEmpty()) lines.add(cur.toString());
            return lines;
        }

        /** The standard fonts take Latin-1 only; anything else would make showText throw. */
        private static String clean(String s) {
            StringBuilder sb = new StringBuilder();
            for (char ch : (s == null ? "" : s).toCharArray()) {
                sb.append(ch >= 0x20 && ch <= 0xFF ? ch : '?');
            }
            return sb.toString();
        }
    }
}
