using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
namespace LZMEncryptAndDecrytAlg
{
    class RSA
    {
        private readonly BigInteger _d;
        private readonly BigInteger _e;
        private readonly BigInteger _n;
        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="Prime_1">素数1,要赋值给p</param>
        /// <param name="Prime_2">素数2，要赋值给q</param>
        /// <param name="Prime_3">素数3，要赋值给e</param>
        private RSA(int Prime_1,
                   int Prime_2, int Prime_3)
        {
            if (!IsPrime(Prime_1) || !IsPrime(Prime_2) || !IsPrime(Prime_3) || Gcd(((Prime_1 - 1) * (Prime_2 - 1)), Prime_3) != 1)
            {
                throw new ArgumentException("输入必须是素数，并且第三个素数不可以是(prime_1 - 1)*(prime_2 -1)的倍数");
            }
            var p = new BigInteger(Prime_1);
            var q = new BigInteger(Prime_2);
            var e = new BigInteger(Prime_3);
            
            _e = (BigInteger)e;
            _n = BigInteger.Multiply(p, q);
            //求phiN
            var phiN = new BigInteger((Prime_1 - 1) * (Prime_2 - 1));
            //e = new BigInteger(65537); //默认的素数
            //求d
            _d = ModInverse(_e, phiN);
        }

        /// <summary>
        /// 默认无参的构造函数
        /// </summary>
        public RSA() : this(1327, 2099, 65537)
        {

        }

        /// <summary>
        /// 加密消息
        /// </summary>
        /// <param name="msg">消息</param>
        /// <returns></returns>
        public BigInteger Encrypt(BigInteger msg)
        {
            return ModPow(msg, _e, _n);
        }

        /// <summary>
        ///解密消息
        /// </summary>
        /// <param name="msg">密文</param>
        public BigInteger Decrypt(BigInteger msg)
        {
            return ModPow(msg, _d, _n);
        }

        /// <summary>
        /// Sieve of Erathosthenes
        ///判断是否是素数
        /// </summary>
        /// <param name="n">素数n</param>
        private bool IsPrime(int n)
        {
            List<bool> boolList = new List<bool>();
            //将列表元素初始化为true
            for (var i = 0; i <= n; i++)
            {
                boolList.Add(true);
            }

            for (var i = 2; i <= n; i++)
            {
                if (boolList[i])
                {
                    var j = i;
                    do
                    {
                        j = j + i;
                        if (j <= n)
                        {
                            boolList[j] = false;
                        }
                    } while (j <= n);
                }
            }
            return boolList.ElementAt(n);
        }

        /// <summary>
        /// 求两数的最大公约数
        /// </summary>
        /// <param name="num_1">数1</param>
        /// <param name="num_2">数2</param>
        public BigInteger Gcd(BigInteger num_1, BigInteger num_2)
        {
            BigInteger rest = -1;
            BigInteger result = -1;

            while (rest != 0)
            {
                rest = num_1 % num_2;

                if (rest != 0)
                {
                    result = rest;
                }

                num_1 = num_2;
                num_2 = (int)rest;
            }
            return result;
        }
        /// <summary>
        /// 根据ad%n=1求出d
        /// </summary>
        /// <param name="a">e</param>
        /// <param name="n">phiN</param>
        /// <returns></returns>
        private BigInteger ModInverse(BigInteger a,
                                      BigInteger n)
        {
            BigInteger i = n,v = 0,d = 1;
            while (a > 0)
            {
                BigInteger t = i / a,x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if (v < 0)
            {
                v = (v + n) % n;
            }
            return v;
        }

        /// <summary>
        /// 计算M^e % n
        /// </summary>
        /// <param name="_base">底数.</param>
        /// <param name="power">指数.</param>
        /// <param name="modulus">模数.</param>
        /// <returns></returns>
        private BigInteger ModPow(BigInteger _base,
                                  BigInteger power,
                                  BigInteger modulus)
        {
            BigInteger result = 1;
            while (power > 0)
            {
                if (!power.IsEven)
                {
                    result = (result * _base) % modulus;
                }
                power >>= 1;
                _base = (_base * _base) % modulus;
            }
            return result;
        }
    }
}