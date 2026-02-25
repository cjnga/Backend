import base64
import io

# Try importing pytesseract + Pillow, provide fallback
try:
    from PIL import Image
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

try:
    import pytesseract
    # Quick check if binary is accessible
    pytesseract.get_tesseract_version()
    OCR_AVAILABLE = True
except Exception:
    OCR_AVAILABLE = False
    print("⚠️  Tesseract OCR not available. Will use OpenAI Vision for images.")


async def extract_text_from_image(base64_image: str) -> str:
    """Extract text from base64-encoded image using OCR."""
    if not OCR_AVAILABLE or not PILLOW_AVAILABLE:
        return "[OCR unavailable]"

    try:
        image_data = base64.b64decode(base64_image)
        image = Image.open(io.BytesIO(image_data))
        text = pytesseract.image_to_string(image)
        return text.strip() if text.strip() else "[OCR unavailable]"
    except Exception as e:
        print(f"OCR error: {e}")
        return "[OCR unavailable]"


async def extract_text_with_openai(base64_image: str, openai_client) -> str:
    """Use OpenAI Vision to extract text from image."""
    try:
        # Clean base64 string — remove data URI prefix if present
        if "," in base64_image[:100]:
            base64_image = base64_image.split(",", 1)[1]

        response = await openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": "Extract ALL text from this image exactly as it appears. Include any URLs, phone numbers, email addresses. Return only the extracted text, nothing else."
                        },
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{base64_image}",
                                "detail": "low"
                            }
                        }
                    ]
                }
            ],
            max_tokens=1500
        )
        extracted = response.choices[0].message.content.strip()
        return extracted if extracted else "[Could not extract text from image]"
    except Exception as e:
        print(f"OpenAI Vision error: {e}")
        return "[Could not extract text from image]"


async def analyze_image_directly(base64_image: str, openai_client) -> dict:
    """Analyze image directly with OpenAI Vision for phishing/scam content.
    Used as last-resort when text extraction fails completely."""
    try:
        if "," in base64_image[:100]:
            base64_image = base64_image.split(",", 1)[1]

        response = await openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": """You are PhishGuard AI. Analyze this image for phishing, scam, or fraud indicators.
Return ONLY valid JSON:
{
  "is_spam": true/false,
  "risk_score": 0-100,
  "risk_level": "safe"|"low"|"medium"|"high"|"critical",
  "verdict": "Short verdict",
  "reasons": ["reason1"],
  "probable_source": "Description of likely origin",
  "source_category": "phishing_email"|"sms_scam"|"fake_website"|"impersonation"|"malware_link"|"lottery_scam"|"job_scam"|"romance_scam"|"tech_support_scam"|"investment_scam"|"legitimate"|"unknown",
  "matched_scam_patterns": [],
  "recommendations": ["What user should do"],
  "confidence": 0.0-1.0
}"""
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": "Analyze this image for phishing, scam, or fraud. Return JSON only."
                        },
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{base64_image}",
                                "detail": "low"
                            }
                        }
                    ]
                }
            ],
            max_tokens=2000,
        )
        import json
        text = response.choices[0].message.content.strip()
        # Remove markdown fencing if present
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
        return json.loads(text)
    except Exception as e:
        print(f"Direct image analysis error: {e}")
        return None
