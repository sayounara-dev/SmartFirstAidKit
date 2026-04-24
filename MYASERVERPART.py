from flask import Flask, request, jsonify
from flask_cors import CORS
import pytesseract
from PIL import Image
import io
import os
app = Flask(__name__)
CORS(app)
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
@app.route('/upload', methods=['POST'])
def upload_image():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        if not file.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
            return jsonify({'error': 'Invalid file format. Use PNG or JPG'}), 400
        image_bytes = file.read()
        image = Image.open(io.BytesIO(image_bytes))
        image = image.convert('L')
        image = image.point(lambda x: 0 if x < 128 else 255, '1')
        text = pytesseract.image_to_string(image, lang='rus')
        return jsonify({
            'success': True,
            'text': text.strip(),
            'filename': file.filename
        })    
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok', 'service': 'OCR API'}), 200
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)