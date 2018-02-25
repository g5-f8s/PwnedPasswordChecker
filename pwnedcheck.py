import argparse, sys, requests, hashlib, getpass
'''
This class uses Troy Hunts https://api.pwnedpasswords.com service to check if a password has been pwned.
It takes only the first 5 characters of the SHA-1 hashed password, and sends this to the service. It then
goes through the returned list of matches, and compares the results. If a match is found, your password
has been pwned. Otherwise, you're ok for now, but should still use password strength checkers to ensure
your password is sufficiently strong. You should also use a password-manager to make sure you generate strong
and unique passwords per site. 
'''
class PwnedPasswordChecker(object):
    
    def checkPassword(self, password):
        hashedPasssword = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        response = requests.get('https://api.pwnedpasswords.com/range/' + hashedPasssword[0:5])

        pwned = False;
        freq = 0;
        for line in response.iter_lines():
            tokens = line.decode('utf-8').split(':')
            if ((hashedPasssword[0:5] + tokens[0]) == hashedPasssword):
                pwned = True
                freq = tokens[1]
                break
        if pwned:
            print ('Your password has been pwned - change it asap! Usage frequency: '+freq+'.')
        else:
            print ('Your password has not been pwned yet!')
        

'''
You can either run this with a password supplied with the '-p' switch, or just run it.
When run without the '-p' switch, it'll run in interactive mode and ask you to supply
a password to check.
'''        
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--password", type=str, help="the password to check")
    args = parser.parse_args()
    password = (args.password, "") [args.password == None]
    
    if not password:
        password = getpass.getpass('Enter password to check:')
        
    PwnedPasswordChecker().checkPassword(password)
    sys.exit(0)