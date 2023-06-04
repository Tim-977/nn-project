import random

def myhash(s):

    def mainalg(s, seed):
        s += '1535_' * 10
        random.seed(seed)
        P = 29 + int(random.random() * 1e4)

        x = 308
        MOD = int(random.random() * x)
        while (x > 0):
            MOD += int(random.random() * 10**x)
            x -= 16
        MOD = int(MOD)

        power = [1 + int(random.random() * 1e3) % 9]

        t = ''
        for i in range(len(s)):
            for j in range(1 + int(random.random() * 1e3) % 10):
                t += chr(33 + int(random.random() * 1e4) % 94)

            t += s[i]
        s = t
        s += '1535_' * 10

        for i in range(1, len(s)):
            power.append(((power[i - 1]) * P + int(1e2 * random.random())) % MOD)

        res = 0
        for i in range(len(s)):
            res += ord(s[i]) * power[i]
            res %= MOD

        return res

    result = ''

    for i in range(1, 100):
        result += str(mainalg(s, i))
    
    return result
