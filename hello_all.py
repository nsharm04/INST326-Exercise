def secret_greeting(num):
    num = int(input("Enter an even number for the secret greeting: "))
    if num % 2 == 0:
        print("Hello all! Welcome to this test repository")
    else: 
        print("Not a correct or accepted number!")
    
secret_greeting(2)

def goodbye():
    print("Goodbye! See you later")
    