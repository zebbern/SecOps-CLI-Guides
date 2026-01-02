#!/usr/bin/env python3
import fitz  # PyMuPDF
import sys
import os

def extract_pdf_text(pdf_path, max_pages=30):
    """Extract text from PDF file"""
    try:
        doc = fitz.open(pdf_path)
        text = []
        total_pages = len(doc)
        pages_to_read = min(max_pages, total_pages)
        
        text.append(f"=== PDF: {os.path.basename(pdf_path)} ===")
        text.append(f"Total pages: {total_pages}")
        text.append(f"Reading first {pages_to_read} pages")
        text.append("=" * 60)
        
        for page_num in range(pages_to_read):
            page = doc[page_num]
            page_text = page.get_text()
            if page_text.strip():
                text.append(f"\n--- Page {page_num + 1} ---\n")
                text.append(page_text)
        
        doc.close()
        return "\n".join(text)
    except Exception as e:
        return f"Error reading {pdf_path}: {str(e)}"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extract_pdf.py <pdf_file>")
        sys.exit(1)
    
    pdf_path = sys.argv[1]
    print(extract_pdf_text(pdf_path))
