using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace LZMEncryptAndDecrytAlg
{
    class Program
    {
        /// <summary>
        /// 判断分组包是否填充过
        /// </summary>
        public static bool Flag=false;
      
        /// <summary>
        /// main函数
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            while (true)
            {
                Flag = false;
                Console.WriteLine("选择DES算法请输入1，选择RSA算法请输入2，选择Playfair算法请输入3：");
                string choice = Console.ReadLine();
                switch(choice)
                {
                    case "1":ExecuteDESAlgorithm(); break;
                    case "2":ExecuteRSAAlgorithm();break;
                    case "3":ExecutePlayfairAlgorithm();break;
                    default:Console.WriteLine("输入不合法！");break;
                }
            }
        }
        public static void ExecuteRSAAlgorithm()
        {
            ExecRSA program = new ExecRSA("Textfile.txt", "encrypted.txt", new RSA(), new ReadFileForRSA());
            program.Execute();
        }
        /// <summary>
        /// 运行PlayFair密码
        /// </summary>
        public static void ExecutePlayfairAlgorithm()
        {
            Console.Write("请输入明文（只允许输入英文字母,单词之间请以空格隔开）:");
            string plainText = Console.ReadLine();
            Console.Write("请输入密钥（只允许输入英文字母）:");
            string key = Console.ReadLine();

            bool isFirst = true;
            string encrypted_msg = string.Empty;
            string decrypted_msg = string.Empty;
            string[] msg = plainText.Split(' ');
            for (int i = 0; i < msg.Length; i++)
            {
                //如果长度为奇数，则在其末尾添上一个x
                if ((msg[i].Length & 1) != 0)
                {
                    msg[i] += "x";
                    Flag = true;
                }
                string encodedMsg = Playfair.Cipher(msg[i], key);
                if (isFirst)
                {
                    encrypted_msg += encodedMsg.ToLower();
                }
                else
                    encrypted_msg += " " + encodedMsg.ToLower();
                string decodedMsg = Playfair.Decipher(encodedMsg, key);
                //如果是填充过的，则要把最后一个字符给删除
                if (Flag)
                {
                    decodedMsg = decodedMsg.ToLower().Substring(0, decodedMsg.Length - 1);
                    Flag = false;
                }
                //存储解密信息
                if (isFirst)
                {
                    decrypted_msg += decodedMsg.ToLower();
                    isFirst = false;
                }
                else
                    decrypted_msg += " " + decodedMsg.ToLower();
            }
            Console.WriteLine("加密后的消息为：{0}\n", encrypted_msg);
            Console.WriteLine("解密后的消息为：{0}\n", decrypted_msg);
        }

        /// <summary>
        /// 运行DES算法
        /// </summary>
        public static void ExecuteDESAlgorithm()
        {
            Console.Write("请输入明文：");
            string plainText = Console.ReadLine();

            Console.Write("请输入密钥：");
            string key = Console.ReadLine();
            //转为字节数组
            byte[] k = Encoding.Unicode.GetBytes(key);
            byte[] msg = Encoding.Unicode.GetBytes(plainText);

            //将密钥转为ulong类型
            ulong myKey = bytesToUlong(k);
            //将明文消息分组加密
            ulong[] myMessage = breakMsgIntoGroups(msg);
            ulong[] en_result = new ulong[myMessage.Length];
            for (int i = 0; i < myMessage.Length; i++)
            {
                //进行加密
                ulong encrypt_result = DES.DESEncrypt(myMessage[i], myKey);
                //将结果存到en_result数组中
                en_result[i] = encrypt_result;
            }
            string msgAfterEncrypt = string.Empty;
            for (int i = 0; i < en_result.Length; i++)
            {
                byte[] tmp = ulongToByteArray(en_result[i]);
                msgAfterEncrypt += Encoding.Unicode.GetString(tmp);
            }
            Console.WriteLine("加密后的结果为：{0}\n", msgAfterEncrypt);
            //进行解密
            ulong[] de_result = new ulong[en_result.Length];
            for (int i = 0; i < en_result.Length; i++)
            {
                ulong decrypt_result = DES.DESDecrypt(en_result[i], myKey);
                de_result[i] = decrypt_result;
            }
            string msgAfterDecrypt = string.Empty;
            for (int i = 0; i < de_result.Length - 1; i++)
            {
                byte[] tmp = ulongToByteArray(de_result[i]);
                msgAfterDecrypt += Encoding.Unicode.GetString(tmp);
            }
            if (!Flag)
            {
                byte[] tmp = ulongToByteArray(de_result[de_result.Length - 1]);
                msgAfterDecrypt += Encoding.Unicode.GetString(tmp);
            }
            //如果填充过，则要把填充的字节去除
            else
            {
                byte[] final = ulongToByteArray(de_result[de_result.Length - 1]);
                int num_of_bytes_to_remove = final[7];
                int num_of_bytes_to_retain = 8 - num_of_bytes_to_remove;
                byte[] real_value = new byte[num_of_bytes_to_retain];
                for (int i = 0; i < num_of_bytes_to_retain; i++)
                    real_value[i] = final[i];
                msgAfterDecrypt += Encoding.Unicode.GetString(real_value);
            }
            Console.WriteLine("解密后的结果为：{0}\n", msgAfterDecrypt);
        }
        /// <summary>
        /// 对加密消息进行分组，每组8个字节
        /// </summary>
        /// <param name="msgBytes">字节数组</param>
        /// <returns></returns>
        public static ulong[] breakMsgIntoGroups(byte[] msgBytes)
        {
            //表示未填充过
            Flag = false;
            //字节数
            int count = msgBytes.Length;
            byte[] group;
            double r = Math.Ceiling(Convert.ToDouble(count)/8);
            //组的大小
            ulong[] result = new ulong[Convert.ToInt32(r)];
            int i = 0;
            int result_count = 0;
            //开始分组,并将分组结果存到result中
            while(i<count)
            {
                group = new byte[8];
                int j = 0;
                for (; j < 8 && i < count; j++)
                {
                    group[j] = msgBytes[i];
                    i++;
                }
                //如果还未结束
                if (i != count)
                {
                    result[result_count++] = bytesToUlong(group);
                }
                //如果已经读到尾部，则group数组未填满的部分要按一定规则填满:
                //少几个元素，就填几个byte 0，除了在最后一个元素指明填了几个，便于解密时去掉
                else
                {
                    //如果j!=8,说明需填充
                    if (j != 8)
                    {
                        //说明这是经过填充的
                        Flag = true;
                        for (int k = j; k < 8; k++)
                        {
                            if (k != 8)
                            {
                                byte extra_adding_element = 0;
                                group[k] = extra_adding_element;
                            }
                            else
                            {
                                //指明填充了几个字节
                                byte flag_byte = (byte)(8 - j);
                                group[k] = flag_byte;
                            }
                        }
                        result[result_count++] = bytesToUlong(group);
                    }
                    //无需填充
                    else
                        result[result_count++] = bytesToUlong(group);
                }
            }
            return result;
        }
        /// <summary>
        /// byte[]转ulong，所以返回的一定是64位
        /// </summary>
        /// <param name="b">字节数组</param>
        /// <returns></returns>
        public static ulong bytesToUlong(byte[] b)
        {
            ulong uL = 0;
            for(int i=0;i<b.Length;i++)
            {
                uL <<= 8;
                uL |= b[i];
            }
            return uL;
        }
        /// <summary>
        /// ulong转byte数组
        /// </summary>
        /// <param name="uL">ulong类型参数</param>
        /// <returns> byte数组</returns>
        public static byte[] ulongToByteArray(ulong uL)
        {
            byte[] b = new byte[8];
            for(int i=0;i<8;i++)
            {
                b[i] = 0;
                b[i] = (byte)((uL >> (64 - 8 * (i + 1))) & 0xFF);
            }
            return b;
        }
    }
}