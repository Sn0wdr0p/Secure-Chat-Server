' Imports the libaries that i will be using
Imports System.Net.Sockets
Imports System.Text
Imports System.Security.Cryptography
Imports System.IO
Imports System.Net
Imports System.Text.RegularExpressions

' Where the code for my server is
Module Server
    Dim clientsList As New Hashtable
    Dim clientKeys As New Hashtable



    ' The routine that is called at load up (first)
    Sub Main()
        'Dim serverSocket As New TcpListener(System.Net.IPAddress.Any, 8888)
        Dim serverSocket As New TcpListener(New IPEndPoint(IPAddress.Any, 8888))
        Dim clientSocket As TcpClient
        Dim counter As Integer
        Dim key() As Byte

        serverSocket.Start()
        msg("Chat Server Started ....")

        'getIP()
        counter = 0

        While (True)
            Try
                counter += 1
                clientSocket = serverSocket.AcceptTcpClient()

                Dim bytesFrom(139) As Byte
                Dim dataFromClient As String
                Dim tempKey() As Byte

                Dim networkStream As NetworkStream = clientSocket.GetStream()
                'networkStream.Read(bytesFrom, 0, CInt(clientSocket.ReceiveBufferSize))
                networkStream.Read(bytesFrom, 0, bytesFrom.Length)
                tempKey = bytesFrom
                'MsgBox(Encoding.Unicode.GetString(tempKey) & "tempkey")

                'Code to send back key
                Using DH As New ECDiffieHellmanCng()
                    Dim myPublicKey() As Byte

                    DH.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash
                    DH.HashAlgorithm = CngAlgorithm.Sha256
                    myPublicKey = DH.PublicKey.ToByteArray()
                    'sendKey()
                    'MsgBox(myPublicKey.Length)
                    networkStream.Write(myPublicKey, 0, myPublicKey.Length)
                    networkStream.Flush()

                    key = DH.DeriveKeyMaterial(CngKey.Import(tempKey, CngKeyBlobFormat.EccPublicBlob))
                    'MsgBox("The key is " & Encoding.Unicode.GetString(key))
                End Using


                'networkStream.Read(bytesFrom, 0, CInt(clientSocket.ReceiveBufferSize))
                'networkStream.Read(bytesFrom, 0, bytesFrom.Length)

                'dataFromClient = System.Text.Encoding.Unicode.GetString(bytesFrom)
                'dataFromClient = dataFromClient.Substring(0, dataFromClient.IndexOf("$"))
                Dim nameBytes(1023) As Byte
                Dim ivBytes(15) As Byte
                networkStream.Read(ivBytes, 0, ivBytes.Length)
                networkStream.Read(nameBytes, 0, nameBytes.Length)

                dataFromClient = unEncryptWOClientNo(nameBytes, key, ivBytes)
                dataFromClient = dataFromClient.Substring(0, dataFromClient.IndexOf("$"))







                clientsList(dataFromClient) = clientSocket
                clientKeys.Add(dataFromClient, key)


                broadcast(dataFromClient & " Joined ", dataFromClient, False)

                'msg(dataFromClient & " Joined chat room ")
                Dim client As New handleClinet
                client.startClient(clientSocket, dataFromClient, clientsList)
            Catch ex As Exception

            End Try
        End While

        clientSocket.Close()
        serverSocket.Stop()
        msg("exit")
        Console.ReadLine()
    End Sub

    Sub msg(ByVal mesg As String)
        mesg.Trim()
        Console.WriteLine(" >> " & mesg)
    End Sub

    Sub getIP()
        'Dim strHostName As String

        'Dim strIPAddress As String

        'strHostName = System.Net.Dns.GetHostName()

        'strIPAddress = System.Net.Dns.GetHostByName(strHostName).AddressList(0).ToString()

        'msg(strHostName)
        'msg(strIPAddress)
        Dim ExternalIP As String
        ExternalIP = (New WebClient()).DownloadString("http://checkip.dyndns.org/")
        ExternalIP = (New Regex("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")) _
                     .Matches(ExternalIP)(0).ToString()
        msg(ExternalIP)
    End Sub

    Private Sub broadcast(ByVal msg As String, ByVal uName As String, ByVal flag As Boolean)
        Dim Item As DictionaryEntry
        For Each Item In clientsList
            'Dim keyitem As DictionaryEntry
            'For Each keyitem In clientKeys
            '    If keyitem = Item Then

            '    End If
            'Next

            Dim broadcastSocket As TcpClient
            broadcastSocket = CType(Item.Value, TcpClient)
            Dim broadcastStream As NetworkStream = broadcastSocket.GetStream()
            Dim tempArray As Array
            Dim key() As Byte = CType(clientKeys.Item(Item.Key), Byte())

            If flag = True Then
                'broadcastBytes = Encoding.Unicode.GetBytes(uName & " says : " & msg)
                tempArray = encryptMsg(key, uName & ": " & msg & "$")


            Else
                'broadcastBytes = Encoding.Unicode.GetBytes(msg)

                tempArray = encryptMsg(key, msg & "$")
            End If


            broadcastStream.Write(tempArray(1), 0, tempArray(1).Length)
            broadcastStream.Flush()



            broadcastStream.Write(tempArray(0), 0, tempArray(0).Length)
            broadcastStream.Flush()


        Next
    End Sub

    Private Function encryptMsg(ByVal key() As Byte, ByVal msg As String)
        Try
            Using aes As New AesCryptoServiceProvider()
                aes.Key = key
                aes.GenerateIV()
                Dim iv = aes.IV
                aes.Padding = PaddingMode.PKCS7
                'aes.Padding = PaddingMode.None
                aes.Mode = CipherMode.CBC

                ' Encrypt the message
                Using ciphertext As New MemoryStream()
                    Using cs As New CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write)
                        Dim plaintextMessage(1023) As Byte
                        plaintextMessage = Encoding.Unicode.GetBytes(msg)
                        cs.Write(plaintextMessage, 0, plaintextMessage.Length)

                        'cs.FlushFinalBlock()

                        cs.Close()
                        'Dim encryptedMessage = ciphertext.ToArray()

                        Dim msgArray(2) As Array

                        msgArray(0) = ciphertext.ToArray()
                        msgArray(1) = iv



                        Return msgArray
                    End Using
                End Using
            End Using
        Catch ex As Exception
            Console.Write(ex)
        End Try
    End Function

    Private Function unEncryptMsg(ByVal encryptedMsg() As Byte, ByVal clno As String, ByVal iv() As Byte)
        Console.Write("Ciphertext Received: " & Encoding.Unicode.GetString(encryptedMsg))

            Try
                Using aes As New AesCryptoServiceProvider()
                    aes.Key = clientKeys.Item(clno)
                    aes.IV = iv
                    'aes.Padding = PaddingMode.PKCS7
                    aes.Padding = PaddingMode.None
                    aes.Mode = CipherMode.CBC

                    ' Decrypt the message
                    Using plaintext As New MemoryStream()
                        Using cs As New CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write)
                            cs.Write(encryptedMsg, 0, encryptedMsg.Length)

                            'cs.FlushFinalBlock()

                            cs.Close()
                            Dim message As String = Encoding.Unicode.GetString(plaintext.ToArray())
                            Return message
                        End Using
                    End Using
                End Using
            Catch ex As Exception
                Console.Write(ex)
            End Try
    End Function

    Private Function unEncryptWOClientNo(ByVal encryptedMsg() As Byte, ByVal key() As Byte, ByVal iv() As Byte)
        Using aes As New AesCryptoServiceProvider()
            aes.Key = key
            aes.IV = iv
            'aes.Padding = PaddingMode.PKCS7
            aes.Padding = PaddingMode.None
            aes.Mode = CipherMode.CBC

            ' Decrypt the message
            Using plaintext As New MemoryStream()
                Using cs As New CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write)
                    cs.Write(encryptedMsg, 0, encryptedMsg.Length)

                    'cs.FlushFinalBlock()

                    cs.Close()
                    Dim message As String = Encoding.Unicode.GetString(plaintext.ToArray())
                    'Console.WriteLine(message)
                    Return message
                End Using
            End Using
        End Using
    End Function

    Private Sub removeClient(ByVal clNo As String)
        clientsList.Remove(clNo)
        clientKeys.Remove(clNo)
    End Sub

    Public Class handleClinet
        Dim clientSocket As TcpClient
        Dim clNo As String
        Dim clientsList As Hashtable
        Dim key() As Byte
        Dim ctThread As Threading.Thread = New Threading.Thread(AddressOf doChat)

        Public Sub startClient(ByVal inClientSocket As TcpClient, ByVal clineNo As String, ByVal cList As Hashtable)
            Me.clientSocket = inClientSocket
            Me.clNo = clineNo
            Me.clientsList = cList
            'Dim ctThread As Threading.Thread = New Threading.Thread(AddressOf doChat)
            ctThread.Start()
        End Sub

        Private Sub doChat()
            'Dim infiniteCounter As Integer
            Dim requestCount As Integer
            Dim bytesFrom(1023) As Byte
            Dim dataFromClient As String
            Dim rCount As String
            requestCount = 0
            Dim networkStream As NetworkStream = clientSocket.GetStream()

            While (True)
                Try
                    requestCount = requestCount + 1




                    Dim ivBytes(15) As Byte
                    'networkStream.Read(bytesFrom, 0, CInt(clientSocket.ReceiveBufferSize))
                    networkStream.Read(ivBytes, 0, ivBytes.Length)
                    networkStream.Flush()




                    'networkStream.Read(bytesFrom, 0, CInt(clientSocket.ReceiveBufferSize))
                    networkStream.Read(bytesFrom, 0, bytesFrom.Length)

                    'dataFromClient = System.Text.Encoding.Unicode.GetString(bytesFrom)
                    Dim cMessage() As Byte = bytesFrom
                    networkStream.Flush()



                    'MsgBox("I got " & Encoding.Unicode.GetString(cMessage))

                    dataFromClient = unEncryptMsg(cMessage, clNo, ivBytes)


                    dataFromClient = dataFromClient.Substring(0, dataFromClient.IndexOf("$"))
                    ' msg("From client - " & clNo & " : " & dataFromClient)
                    rCount = Convert.ToString(requestCount)

                    broadcast(dataFromClient, clNo, True)
                Catch ex As Exception
                    ' MsgBox(ex)
                    removeClient(clNo)
                    ctThread.Abort()
                End Try
            End While
        End Sub
    End Class
End Module
