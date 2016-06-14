using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace LZMEncryptAndDecrytAlg
{
    /// <summary>
    /// 为RSA读写文件.
    /// </summary>
    public class ReadFileForRSA
    {
        /// <summary>
        ///从指定路径读文件返回byte数组
        /// </summary>
        /// <param name="filepath">文件路径.</param>
        public byte[] Read(string filepath)
        {
            if (!File.Exists(filepath))
            {
                throw new ArgumentException("路径不存在！");
            }
            else
            {
                try
                {
                    return File.ReadAllBytes(filepath);
                }
                catch (IOException)
                {
                    throw new Exception("无法读取文件！");
                }
            }
        }
    }
    class ExecRSA
    {
        private string textFilePath;
        private string filePathForDecryption;
        private ReadFileForRSA fileRead;
        private bool readableConsole;
        private RSA myRsa;

        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="textfilePath">要加密的文件路径</param>
        /// <param name="filepathForDecryption">解密后的输出文件路径.</param>
        /// <param name="rsa">要用的RSA对象</param>
        /// <param name="fileRead">读取文件</param>
        /// <param name="readableConsole">输出到控制台</param>
        public ExecRSA(string textfilePath, string filepathForDecryption, RSA rsa, ReadFileForRSA fileRead,
            bool readableConsole = true)
        {
            textFilePath = textfilePath;
            filePathForDecryption = filepathForDecryption;
            myRsa = rsa;
            this.fileRead = fileRead;
            this.readableConsole = readableConsole;
        }

        /// <summary>
        /// Executes this instance.
        /// It will read the file, encrypt it, decrypt it again and saves the result to 'out.txt'.
        /// Every step will be visible in the console.
        /// </summary>
        public void Execute()
        {
            //将文件中的数据读到readBytes中
            byte[] readBytes = fileRead.Read(textFilePath);
            //将readBytes的元素复制到BigInteger的列表中
            List<BigInteger> readInts = readBytes.Select(x => new BigInteger(x)).ToList();
            //打印读取文件信息
            PrintCollection(readInts, String.Format("从：\\bin\\Debug\\{0} 中读取信息:", textFilePath));
            //开始把readInts中的每个元素投影到加密函数中进行加密，并把加密结果存到encryptedInts中
            var encryptedInts = readInts.Select(myRsa.Encrypt).ToArray();
            PrintCollection(encryptedInts, "加密的结果为：");
            try
            {
                int elementsInARow = 1;
                String text = "";
                foreach (int k in encryptedInts)
                {
                    text += k;
                    text += " ";
                    if (elementsInARow == 7)
                    {
                        text += "\n";
                        elementsInARow = 0;
                    }
                    elementsInARow++;
                }

                File.WriteAllText("encrypted.txt", text);
                Console.WriteLine("\n请去 '\\bin\\Debug\\encrypted.txt' 文件下查看加密后的文件.");
            }
            catch (Exception e)
            {
                Console.WriteLine("\n无法向文件写入: {0},{1}", e, e.StackTrace);
            }
            string decryptedString = "";
            //如果解密文件名已经存在
            if (filePathForDecryption != null)
            {
                decryptedString = File.ReadAllText(filePathForDecryption);
            }
            //用空格代替换行
            decryptedString = decryptedString.Replace('\n', ' ');
            //以空格为分隔符
            string[] decrypt = decryptedString.Split(' ');
            
            List<BigInteger> decryptliste = new List<BigInteger>();

            //把它们放到list中
            for (int i = 0; i < decrypt.Length; ++i)
            {
                try
                {
                    int num1;
                    bool Parsable = Int32.TryParse(decrypt[i], out num1);
                    {
                        //如果无法解析，不必加到列表中 
                        if (Parsable)
                        {
                            decryptliste.Add(Int32.Parse(decrypt[i]));
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("无法解析加密文件", e, e.StackTrace);
                }
            }
            //放到数组中
            var decryptedArray = decryptliste.ToArray();

            //开始解密每个元素
            var decryptedInfo = decryptedArray.Select(myRsa.Decrypt).ToArray();
            //打印信息
            PrintCollection(decryptedInfo, "解密后的数据:");
            byte[] crypt_byte = decryptedInfo.Select(x => Convert.ToByte((int)x)).ToArray();
            try
            {
                //Write the Text in the File 
                File.WriteAllBytes("decrypted.txt", crypt_byte);
                Console.WriteLine("\n可以在 '\\bin\\Debug\\decrypted.txt'查看解密后的文件\n.");
            }
            catch (Exception e)
            {
                Console.WriteLine("\n无法写入文件: {0},{1}", e, e.StackTrace);
            }
        }

        /// <summary>
        /// 打印输出信息
        /// </summary>
        /// <param name="collection">The collection.</param>
        /// <param name="headline">The headline.</param>
        private void PrintCollection(IEnumerable<BigInteger> collection, string headline)
        {
            Console.WriteLine();
            Console.WriteLine("{0}", headline);

            string underlining = string.Empty;
            for (int i = 0; i < headline.Length; i++)
            {
                underlining += "=";
            }
            Console.WriteLine(underlining);

            if (readableConsole)
            {
                foreach (int i in collection.Take(10))
                {
                    Console.Write(i + " ");
                }
                Console.Write("...");
            }
            else
            {
                foreach (int i in collection)
                {
                    Console.Write(i + " ");
                }
            }
            Console.WriteLine();
        }
    }
}