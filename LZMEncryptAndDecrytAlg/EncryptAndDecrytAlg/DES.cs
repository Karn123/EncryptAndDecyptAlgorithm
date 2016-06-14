using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace LZMEncryptAndDecrytAlg
{
    class DES
    {
        /// <summary>
        /// 置换选择1
        /// </summary>
        public static int[] PC1 =
        {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        };
        /// <summary>
        /// 置换选择2
        /// </summary>
        public static int[] PC2 =
        {
            14, 17, 11, 24, 1,  5,  3,  28,
            15, 6,  21, 10, 23, 19, 12, 4,
            26, 8,  16, 7,  27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56,
            34, 53, 46, 42, 50, 36, 29, 32
        };
        /// <summary>
        /// 初始置换IP
        /// </summary>
        public static int[] IP =
        {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };
        /// <summary>
        /// 逆初始置换IPINV，也就是Final Permutation
        /// </summary>
        public static int[] FP =
        {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9,  49, 17, 57, 25
        };
        /// <summary>
        /// 扩展置换E
        /// </summary>
        public static int[] E =
        {
            32, 1,  2,  3,  4,  5,
            4,  5,  6,  7,  8,  9,
            8,  9,  10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32,  1
        };
        /// <summary>
        /// 置换函数P
        /// </summary>
        public static int[] P =
        {
            16, 7,  20, 21, 29, 12, 28, 17,
            1,  15, 23, 26, 5,  18, 31, 10,
            2,  8,  24, 14, 32, 27, 3,  9,
            19, 13, 30, 6,  22, 11, 4,  25
        };
        /// <summary>
        /// S盒(共8个4*16的盒子，先用一维数组代替)，每个S盒输入6位（1、6位决定行号，剩下4位决定列号），输出4位，
        /// </summary>
        public static byte[,] SBoxes =
        {
            //S1
            {
                14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
            },
            //S2
            {
                15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
            },
            //S3
            {
                10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
            },
            //S4
            {
                7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
            },
            //S5
            {
                2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
            },
            //S6
            {
                12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
            },
            //S7
            {
                4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
            },
            //S8
            {
                13, 2, 8,  4, 6, 15, 11, 1, 10,  9,  3, 14,  5,  0, 12, 7,
                1, 15, 13, 8, 10, 3,  7, 4, 12,  5,  6, 11,  0, 14,  9, 2,
                7, 11, 4,  1, 9, 12, 14, 2,  0,  6, 10, 13, 15,  3,  5, 8,
                2, 1,  14, 7, 4, 10,  8,13, 15, 12,  9,  0,  3,  5,  6, 11
            }
        };
        
        /// <summary>
        /// 每轮迭代时左移次数的确定
        /// </summary>
        public static int[] LeftShiftChoice = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
       
        /// <summary>
        /// 置换
        /// </summary>
        /// <param name="val">输入值</param>
        /// <param name="changes">选择置换的方案（如IP初始置换）</param>
        /// <returns></returns>
        public static ulong Permute(ulong val, int[] changes)
        {
            ulong result = 0;
            const int size = sizeof(ulong) * 8; //size=64

            for (int i = 0; i < changes.Length; i++)
            {
                //将result的第i位置换为第change[i]位，则要拿到第change[i]位，需要将val向右移size-change[i]位（因为编号为1-64不是0-63）
                ulong bit = val >> (size - changes[i]) & 1;
                //bit要么是0，要么是1，将它左移size-i-1位，与result进行或运算
                result =result | (bit << (size - i - 1) );
            }
            return result;
        }

        
        /// <summary>
        /// 拿到56位的左28位，返回类型是左28位+36个0
        /// </summary>
        /// <param name="val"></param>
        /// <returns></returns>
        public static ulong getLeft28(ulong val)
        {
            return val & 0xFFFFFFF000000000;
        }

        /// <summary>
        /// 拿到56位的右28位。返回的ulong类型是右28位+36个0
        /// </summary>
        /// <param name="val"></param>
        /// <returns></returns>
        public static ulong Right28(ulong val)
        {
            return (val << 28) & 0xFFFFFFF000000000;
        }
        
        /// <summary>
        /// 将左28位与右28位接起来，变成56位
        /// </summary>
        /// <param name="left">左28位</param>
        /// <param name="right">右28位</param>
        /// <returns></returns>
        public static ulong LinkLeft28AndRight28(ulong left, ulong right)
        {
            return (left & 0xFFFFFFF000000000) | ((right & 0xFFFFFFF000000000) >> 28);
        }

        /// <summary>
        /// 将val循环左移count位
        /// </summary>
        /// <param name="val">输入值</param>
        /// <param name="count">循环左移的位数</param>
        /// <returns></returns>
        public static ulong LeftShift(ulong val, int count)
        {
            for (int i = 0; i < count; i++)
            {
                //取28位中的最高位，因为通过Left28和Right28得到的28是高位，低位全为0
                ulong tmp = val & 0x8000000000000000;
                //循环左移1位，即先左移一位，与0xFFFFFFE000000000相与（即第28位为0），再和tmp右移27位进行或运算得到最后一位（即将28位的最高位赋给28位的最低位）
                val = (val << 1) & 0xFFFFFFE000000000 | (tmp >> 27);
            }
            return val;
        }

        /// <summary>
        /// 将48位的数据分为8个，每组6个
        /// </summary>
        /// <param name="val">48高位的值，其余低位为0</param>
        /// <returns>8个6位2进制列表</returns>
        public static List<byte> Split(ulong val)
        {
            var group = new List<byte>();
            for (int i = 0; i < 8; i++)
            {
                //取前6位，右移56位后，6位后两位是0（一个byte8位，保持6位在高位）
                group.Add((byte)((val & 0xFC00000000000000) >> 56));
                //左移6位
                val <<= 6;
            }
            return group;
        }
        
        /// <summary>
        /// 对64位密钥进行操作
        /// </summary>
        /// <param name="key">密钥</param>
        /// <returns></returns>
        public static List<ulong> HandleKey(ulong key)
        {
            //进行PC1置换
            ulong after_pc1 = Permute(key, PC1);
            //得到左28位
            ulong left_28 = getLeft28(after_pc1);
            //得到右28位
            ulong right_28 = Right28(after_pc1);
            //创建左右对的列表，并将left_28和right_28加入作为第一轮使用的对
            var schedule = new List<Pair> { new Pair { Left = left_28, Right = right_28 } };
            //根据每轮左移位数表，依次进行循环左移的迭代，得到每轮的left和right对
            for (int i = 1; i <= LeftShiftChoice.Count(); i++)
            {
                schedule.Add(new Pair
                {
                    Left = LeftShift(schedule[i - 1].Left, LeftShiftChoice[i - 1]),
                    Right = LeftShift(schedule[i - 1].Right, LeftShiftChoice[i - 1])
                });
            }
            //创建一个表，用来存56位数据进行置换选择2（即PC2）后得到的每轮的K
            var result = new List<ulong>();
            //开始对每轮的56位数据进行PC2置换，并将每轮的结果存到result列表里
            for (int i = 0; i < schedule.Count; i++)
            {
                ulong joined = LinkLeft28AndRight28(schedule[i].Left, schedule[i].Right);
                ulong k = Permute(joined, PC2);
                result.Add(k);
            }
            return result;
        }
        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="message">要加密的消息</param>
        /// <param name="key">密钥</param>
        /// <returns></returns>
        public static ulong DESEncrypt(ulong message, ulong key)
        {
            //对明文进行初始置换
            ulong ip = Permute(message, IP);
            //K就是经过PC2置换之后得到的每轮密钥Ki(i=1~16)的集合
            List<ulong> K = HandleKey(key);
            //将初始置换得到的ip分为左右各32位
            Pair pair = new Pair
            {
                Left = ip & 0xFFFFFFFF00000000,
                Right = (ip & 0x00000000FFFFFFFF) << 32
            };
            //开始进行16轮变换
            for (int i = 0; i < 16; i++)
            {
                pair = new Pair
                {
                    Left = pair.Right,
                    Right = pair.Left ^ F(pair.Right, K[i + 1])
                };
            }
            //左32位与右32位交换位置
            ulong joined = pair.Right | (pair.Left >> 32);
            //进行逆初始置换，也就是最后的置换
            return Permute(joined, FP);
        }
        /// <summary>
        /// DES解密算法，和加密一样，只不过密钥Ki使用顺序相反
        /// </summary>
        /// <param name="message"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static ulong DESDecrypt(ulong message, ulong key)
        {
            //对明文进行初始置换
            ulong ip = Permute(message, IP);
            //K就是经过PC2置换之后得到的每轮密钥Ki(i=1~16)的集合
            List<ulong> K = HandleKey(key);
            //将初始置换得到的ip分为左右各32位
            Pair pair = new Pair
            {
                Left = ip & 0xFFFFFFFF00000000,
                Right = (ip & 0x00000000FFFFFFFF) << 32
            };
            //开始进行16轮变换,密钥是倒着用的
            for (int i = 16; i >=1 ; i--)
            {
                pair = new Pair
                {
                    Left = pair.Right,
                    Right = pair.Left ^ F(pair.Right, K[i])
                };
            }
            //左32位与右32位交换位置
            ulong joined = pair.Right | (pair.Left >> 32);
            //进行逆初始置换，也就是最后的置换
            return Permute(joined, FP);
        }
        /// <summary>
        /// 根据6位2进制输入val和对应的S盒，返回4位2进制位（S盒表中的数据值为0~15，每个值都用4位2进制表示）
        /// </summary>
        /// <param name="val">6位的输入</param>
        /// <param name="table_S">第几个S盒</param>
        /// <returns>4位2进制位</returns>
        public static byte SBoxLookup(byte val, int table_S)
        {
            //6位2进制的最高位和最低位决定S盒行号（最高位向右移2位，最低位向左移2位，异或后就变得相邻了，结果存在第3、4位中），
            //6位2进制的中间四位决定S盒列号（val & 0x78 拿到中间4位，即第2~5位，再向右移3位，它们就存在于第5~8位），
            //所以index转化为2进制后的后6位就存着行号和列号的值。
            //这里由于每个S盒是一维数组，也就是6位2进制所表示的值代表对应S盒一维数组的下标(6位2进制范围为0-63,与4*16的二维数组是等价的)
            int index = ((val & 0x80) >> 2) | ((val & 0x04) << 2) | ((val & 0x78) >> 3);
            return SBoxes[table_S, index];
        }
        /// <summary>
        /// F函数
        /// </summary>
        /// <param name="right">右32位（处于高32位，剩下32位为0）</param>
        /// <param name="key">每轮的key</param>
        /// <returns></returns>
        public static ulong F(ulong right, ulong key)
        {
            //对右32位首先进行E置换（扩展置换），变为48位
            ulong extended = Permute(right, E);
            //二者异或
            ulong x = extended ^ key;
            //将x分解为8个bytes（高六位为数据位,6*8=48）
            List<byte> bytesAfterSplit = Split(x);
            //用于存储每次遍历盒子后得到的4位2进制，8个盒子最后存的是32位
            ulong boxTraverse = 0;
            //为8个6位2进制数据值分别进行S盒操作
            for (int i = 0; i < 8; i++)
            {
                //左移四位，保存上一个盒子返回的4位2进制值
                boxTraverse <<= 4;
                //得到下一个盒子返回的4位2进制值并存到boxLookup中
                boxTraverse |= SBoxLookup(bytesAfterSplit[i], i);
            }
            //左移32位，因为上个循环共左移了32位，所以低32位为有效数据位，现在把它变为高32位
            boxTraverse <<= 32;
            //对这32位数据进行P置换
            ulong result = Permute(boxTraverse, P);
            //返回置换结果
            return result;
        }
    }

    /// <summary>
    /// 分割密钥后左右对
    /// </summary>
    public struct Pair
    {
        public ulong Left;
        public ulong Right;
    }
}