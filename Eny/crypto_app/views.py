
from django.shortcuts import render
from django.http import JsonResponse
from .utils import CryptoUtils

def index(request):
    result_encrypt = ""
    result_decrypt = ""
    error = None

    if request.method == "POST" and ('encrypt' in request.POST or 'decrypt' in request.POST):
        algorithm = request.POST.get('algorithm', 'otp')
        message = request.POST.get('message')
        key = request.POST.get('key')
        decrypt_input = request.POST.get('decrypt_input')

        try:
            if 'encrypt' in request.POST:
                if algorithm == 'otp':
                    if len(key) < len(message or ''):
                        raise ValueError("For OTP, key must be at least as long as the message.")
                    result_encrypt = CryptoUtils.otp_encrypt(message, key)
                elif algorithm == 'aes':
                    result_encrypt = CryptoUtils.aes_encrypt(message, key)
                elif algorithm == '3des':
                    result_encrypt = CryptoUtils.des3_encrypt(message, key)
            elif 'decrypt' in request.POST:
                if algorithm == 'otp':
                    result_decrypt = CryptoUtils.otp_decrypt(decrypt_input, key)
                elif algorithm == 'aes':
                    result_decrypt = CryptoUtils.aes_decrypt(decrypt_input, key)
                elif algorithm == '3des':
                    result_decrypt = CryptoUtils.des3_decrypt(decrypt_input, key)
        except Exception as e:
            error = str(e)

        return JsonResponse({
            'result_encrypt': result_encrypt,
            'result_decrypt': result_decrypt,
            'error': error
        })

    # For non-AJAX requests, render the template
    return render(request, 'crypto_app/index.html', {
        'result_encrypt': result_encrypt,
        'result_decrypt': result_decrypt,
        'algorithm': request.POST.get('algorithm', 'otp')
    })