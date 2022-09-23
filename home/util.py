import string
import random

def random_generator():
    
    letters = string.ascii_letters
    digits = string.digits
    special_character = "!#$@%&"
    result_str = ''.join(random.choice(letters) for i in range(10)) + ''.join(random.choice(digits) for i in range(6)) + ''.join(random.choice(special_character) for i in range(4))
    
    return ''.join(random.sample(result_str, len(result_str)))
