package org.tsicoop.privacyvault.framework;

import java.io.OutputStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
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
            }

            document.save(out); // Stream directly to HTTP response
        }
    }
}