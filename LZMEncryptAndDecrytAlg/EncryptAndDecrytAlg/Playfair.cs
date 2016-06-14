using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LZMEncryptAndDecrytAlg
{

    /// <summary>
    ///playfair算法
    /// </summary>
    class Playfair
    {
        /// <summary>
        /// A的ASCII码
        /// </summary>
        const int A = 65;
        /// <summary>
        /// J的ASCII码
        /// </summary>
        const int J = 74;
        /// <summary>
        /// Z的ASCII码
        /// </summary>
        const int Z = 90;
        /// <summary>
        /// playfair表
        /// </summary>
        char[] playfairSeq;
        /// <summary>
        /// 表格数组大小
        /// </summary>
        const int AlphabetLength = 25;
        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="keyword">密钥词</param>
        public Playfair(string keyword)
        {
            //将密钥词填充到表里
            this.playfairSeq = CreatePlayfairSeq(keyword);
        }

        /// <summary>
        /// 加密明文
        /// </summary>
        /// <param name="plaintext">待加密的明文</param>
        /// <returns>返回加密结果</returns>
        public string Encode(string plaintext)
        {
            return Cipher(plaintext, this.playfairSeq);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="encryptedText">待解密的字符串.</param>
        /// <returns>返回解密后的字符串.</returns>
        public string Decipher(string encryptedText)
        {
            return Decipher(encryptedText, this.playfairSeq);
        }

        /// <summary>
        /// 加密函数
        /// </summary>
        /// <param name="plaintext">要加密的明文</param>
        /// <param name="playfairLine">根据密钥创建的playFairLine</param>
        /// <returns>返回加密结果</returns>
        public static string Cipher(string plaintext, char[] playfairLine)
        {
            char[] text = plaintext.ToUpper().ToCharArray();
            StringBuilder result = new StringBuilder(text.Length);
            int[] firstLetterPosInPair = new int[2];
            int[] secondLetterPosInPair = new int[2];
            for (int i = 0; i < text.Length; i++)
            {
                // 对于偶数，找到其所在二维数组的下标后进入下一次循环
                if ((i & 1) == 0)
                {
                    firstLetterPosInPair = SearchInArray(text[i], playfairLine);
                    continue;
                }
                //对于奇数，pos代表该字母所在二维数组的下标，并和上一个字母组对
                secondLetterPosInPair = SearchInArray(text[i], playfairLine);
                //如果同行,则用右边的字母代替（最后一个就由第一个代替）
                if (firstLetterPosInPair[0] == secondLetterPosInPair[0])
                {
                    firstLetterPosInPair[1]++;
                    //当firstLetterPosInPair[1]=5的时候，把它变为0
                    firstLetterPosInPair[1] -= ((firstLetterPosInPair[1] * 7) >> 5) * 5;
                    secondLetterPosInPair[1]++;
                    secondLetterPosInPair[1] -= ((secondLetterPosInPair[1] * 7) >> 5) * 5;
                    //若既同行又同列（即字母相同）
                    if (firstLetterPosInPair[1] == secondLetterPosInPair[1])
                    {
                        firstLetterPosInPair[0]++;
                        firstLetterPosInPair[0] -= ((firstLetterPosInPair[0] * 7) >> 5) * 5;
                        secondLetterPosInPair[0]++;
                        secondLetterPosInPair[0] -= ((secondLetterPosInPair[0] * 7) >> 5) * 5;
                        result.Append(playfairLine[(firstLetterPosInPair[0] * 5) + firstLetterPosInPair[1]]);
                        result.Append(playfairLine[(secondLetterPosInPair[0] * 5) + secondLetterPosInPair[1]]);
                        continue;
                    }
                }
                //如果同列，则字母对中的字母用下面一个字母来代替
                else if (firstLetterPosInPair[1] == secondLetterPosInPair[1])
                {
                    firstLetterPosInPair[0]++;
                    firstLetterPosInPair[0] -= ((firstLetterPosInPair[0] * 7) >> 5) * 5;
                    secondLetterPosInPair[0]++;
                    secondLetterPosInPair[0] -= ((secondLetterPosInPair[0] * 7) >> 5) * 5;
                }
                //若既不同行又不同列，该字母所在列为上一个字母所在列，上一个字母所在列为该字母所在列
                else
                {
                    int buffer = firstLetterPosInPair[1];
                    firstLetterPosInPair[1] = secondLetterPosInPair[1];
                    secondLetterPosInPair[1] = buffer;
                }
                //把该字母对插到表中
                result.Append(playfairLine[(firstLetterPosInPair[0] * 5) + firstLetterPosInPair[1]]);
                result.Append(playfairLine[(secondLetterPosInPair[0] * 5) + secondLetterPosInPair[1]]);
            }
            return result.ToString();
        }

        /// <summary>
        /// 解密消息
        /// </summary>
        /// <param name="encryptedText">待解密消息</param>
        /// <param name="playfairLine">palyfairLine字符数组</param>
        /// <returns>返回解密信息</returns>
        public static string Decipher(string encryptedText, char[] playfairLine)
        {
            char[] text = encryptedText.ToUpper().ToCharArray();
            StringBuilder result = new StringBuilder(text.Length);

            int[] firstLetterPos = new int[2];
            int[] secondLetterPos = new int[2];
            for (int i = 0; i < text.Length; i++)
            {
                // 对于偶数
                if ((i & 1) == 0)
                {
                    firstLetterPos = SearchInArray(text[i], playfairLine);
                    continue;
                }
                secondLetterPos = SearchInArray(encryptedText[i], playfairLine);
                //同行
                if (firstLetterPos[0] == secondLetterPos[0])
                {
                    firstLetterPos[1] += 9;
                    firstLetterPos[1] -= ((firstLetterPos[1] * 7) >> 5) * 5;
                    secondLetterPos[1] += 9;
                    secondLetterPos[1] -= ((secondLetterPos[1] * 7) >> 5) * 5;
                    //若两个字母相同
                    if (firstLetterPos[1] == secondLetterPos[1])
                    {
                        firstLetterPos[0] += 9;
                        firstLetterPos[0] -= ((firstLetterPos[0] * 7) >> 5) * 5;
                        secondLetterPos[0] += 9;
                        secondLetterPos[0] -= ((secondLetterPos[0] * 7) >> 5) * 5;
                        result.Append(playfairLine[(firstLetterPos[0] * 5) + firstLetterPos[1]]);
                        result.Append(playfairLine[(secondLetterPos[0] * 5) + secondLetterPos[1]]);
                        continue;
                    }
                }
                //同列
                else if (firstLetterPos[1] == secondLetterPos[1])
                {
                    firstLetterPos[0] += 9;
                    firstLetterPos[0] -= ((firstLetterPos[0] * 7) >> 5) * 5;
                    secondLetterPos[0] += 9;
                    secondLetterPos[0] -= ((secondLetterPos[0] * 7) >> 5) * 5;
                }
                //其他
                else
                {
                    int buffer = firstLetterPos[1];
                    firstLetterPos[1] = secondLetterPos[1];
                    secondLetterPos[1] = buffer;
                }
                result.Append(playfairLine[(firstLetterPos[0] * 5) + firstLetterPos[1]]);
                result.Append(playfairLine[(secondLetterPos[0] * 5) + secondLetterPos[1]]);
            }
            return result.ToString();
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="plaintext">加密明文</param>
        /// <param name="keyword">密钥</param>
        /// <returns>返回加密结果</returns>
        public static string Cipher(string plaintext, string keyword)
        {
            return Cipher(plaintext, CreatePlayfairSeq(keyword));
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="encryptedText">待解密消息.</param>
        /// <param name="keyword">密钥</param>
        /// <returns>返回解密消息</returns>
        public static string Decipher(string encryptedText, string keyword)
        {
            return Decipher(encryptedText, CreatePlayfairSeq(keyword));
        }

        /// <summary>
        /// 根据给定密钥词填充到表里
        /// </summary>
        /// <param name="key">密钥词</param>
        /// <returns>返回char[]</returns>
        public static char[] CreatePlayfairSeq(string key)
        {
            char[] input = key.ToUpper().ToCharArray();
            
            char[] alphabet = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
            char[] result = new char[25];
            bool[] given = new bool[25];

            int count = 0;
            //填到表里
            for (int i = 0; i < input.Length; i++)
            {
                int charValue = (int)input[i];
                // J以后的字母，charValue要减一，才能保证填到正确位置
                if (charValue >= J)
                {
                    charValue--;
                }
                //去掉重复字母
                if (!given[charValue - A])
                {
                    given[charValue - A] = true;
                    result[count++] = input[i];
                }
            }
            // 将密钥剩下的字母填到数组里
            if (count < AlphabetLength)
            {
                for (int i = 0; i < AlphabetLength; i++)
                {
                    if (!given[i])
                    {
                        result[count++] = alphabet[i];
                    }
                }
            }
            return result;
        }
        /// <summary>
        /// 把一维数组等价于5*5的二维数组后，返回所在的二维数组的下标
        /// </summary>
        /// <param name="c">要找的字符</param>
        /// <param name="array">字符数组</param>
        /// <returns>返回一个一维数组，第一个元素表示行号，第二个表示列号</returns>
        private static int[] SearchInArray(char c, char[] array)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (array[(i * 5) + j] == c)
                    {
                        return new int[] { i, j };
                    }
                }
            }
            return null;
        }
    }
}