//using iText.Kernel.Geom;
//using iText.Kernel.Pdf;
//using iText.Signatures;
using iText.Commons.Bouncycastle.Asn1;
using iText.Commons.Bouncycastle.Asn1.X500;
using iText.Commons.Bouncycastle.Cert;
using iText.Commons.Bouncycastle.Crypto;
using iText.Commons.Bouncycastle.Math;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.X509;
using System.Collections;
using System.Text;
//using System.Security.Cryptography.X509Certificates;
using XAct.Users;
using XSystem.Security.Cryptography;
//using X509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate;

namespace MCDRDigitalSignatureClient.Controllers
{


    class MyExternalSignatureContainer : IExternalSignatureContainer
    {
        public byte[] Data;
        public void ModifySigningDictionary(PdfDictionary signDic)
        {
            throw new NotImplementedException();
        }

        public byte[] getData()
        {
            return this.Data;
        }

        public byte[] Sign(Stream inputStream)
        {

            this.Data = DigestAlgorithms.Digest(inputStream, DigestAlgorithms.SHA256);
            return new byte[0];
            /*
            try
            {
                

                PrivateKeySignature signature = new PrivateKeySignature(new PrivateKeyBC(pk), "SHA256");
                String digestAlgorithmName = signature.GetDigestAlgorithmName();

                IX509Certificate[] certificateWrappers = new IX509Certificate[chain.Length];
                for (int i = 0; i < certificateWrappers.Length; ++i)
                {
                    certificateWrappers[i] = new X509CertificateBC(chain[i]);
                }
                PdfPKCS7 sgn = new PdfPKCS7(null, certificateWrappers, digestAlgorithmName, false);
                byte[] hash = DigestAlgorithms.Digest(inputStream, digestAlgorithmName);
                byte[] sh = sgn.GetAuthenticatedAttributeBytes(hash, PdfSigner.CryptoStandard.CMS,
                    null, null);
                byte[] extSignature = signature.Sign(sh);
                sgn.SetExternalSignatureValue(extSignature, null, signature.GetSignatureAlgorithmName());

                return sgn.GetEncodedPKCS7(hash, PdfSigner.CryptoStandard.CMS, null,
                    null, null);
            }
            catch (IOException ioe)
            {
                throw new Exception(ioe.Message);
            }
                */
        }


        [ApiController]
        [Route("[controller]")]
        public class SignerController : Controller
        {
            public IActionResult Index()
            {
                return View();
            }

            [HttpPost(Name = "preparePDF")]
            /*public byte[] testFunctions()
            {
                string src = "C:\\Users\\ye7ia\\Desktop\\Doc1.pdf";
                string dest = "C:\\Users\\ye7ia\\Desktop\\Doc1_signAgilityTest.pdf";
                X509Certificate[] certificates = null;
                X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                my.Open(OpenFlags.ReadOnly);
                certificates = my.Certificates.Find(X509FindType.FindBySerialNumber, "724e3ce5e791ac3b5c4512324955d649", false)[0];
                if (certificates.Length == 0) throw new Exception("No certificates found.");

                return EmptySignature(src, dest, "field", certificates);
            }
            */

            // Frontend Module
            /*public byte[] signHash(string hashBase64,X509Certificate cert)
            {
                byte[] signedHash;
                byte[] hash = Convert.FromBase64String(hashBase64);

                // sign the hash

                return signedHash;

            }
            */


            // Backend Module
            public string EmptySignature(String src, String dest, String fieldname, X509Certificate[] chain)
            {
                PdfReader reader = new PdfReader(src);
                PdfSigner signer = new PdfSigner(reader, new FileStream(dest, FileMode.Create), new StampingProperties());

                PdfSignatureAppearance appearance = signer.GetSignatureAppearance();
                appearance
                    .SetPageRect(new Rectangle(36, 748, 200, 100))
                    .SetPageNumber(1)
                    .SetCertificate(new iText.Bouncycastle.X509.X509CertificateBC(chain[0]));
                signer.SetFieldName(fieldname);

                /* ExternalBlankSignatureContainer constructor will create the PdfDictionary for the signature
                 * information and will insert the /Filter and /SubFilter values into this dictionary.
                 * It will leave just a blank placeholder for the signature that is to be inserted later.
                 */
                MyExternalSignatureContainer external = new MyExternalSignatureContainer();

                // Sign the document using an external container
                // 8192 is the size of the empty signature placeholder.
                signer.SignExternalContainer(external, 8192);
                var hash = external.Data;

                PdfPKCS7 signature = new PdfPKCS7(null, (iText.Commons.Bouncycastle.Cert.IX509Certificate[])chain, "SHA265", false);
                var authAttributes = signature.GetAuthenticatedAttributeBytes(hash,PdfSigner.CryptoStandard.CMS,null,null);
                return Convert.ToBase64String(SHA256Managed.Create().ComputeHash(authAttributes));
            }


            // Backend Module
            public static void signPdf(string tempFile, string targetFile, X509Certificate[] chain, byte[] hash, byte[] signedHash)
            {
                using (PdfReader reader = new PdfReader(tempFile))
                {
                    using (FileStream outStream = System.IO.File.OpenWrite(targetFile))
                    {
                        //var signedContainer = new SignedSignatureContainer(hash, signedHash, chain);
                        PdfSigner signer = new PdfSigner(reader, outStream, new StampingProperties());
                        //PdfSigner.SignDeferred(reader,"field",outStream,SignedSignatureContainer);
                    }
                }
            }






        }

        public class cert : IX509Certificate
        {
            public void CheckValidity(DateTime time)
            {
                throw new NotImplementedException();
            }

            public ISet<string> GetCriticalExtensionOids()
            {
                throw new NotImplementedException();
            }

            public byte[] GetEncoded()
            {
                throw new NotImplementedException();
            }

            public string GetEndDateTime()
            {
                throw new NotImplementedException();
            }

            public IList GetExtendedKeyUsage()
            {
                throw new NotImplementedException();
            }

            public IAsn1OctetString GetExtensionValue(string oid)
            {
                throw new NotImplementedException();
            }

            public IX500Name GetIssuerDN()
            {
                throw new NotImplementedException();
            }

            public DateTime GetNotBefore()
            {
                throw new NotImplementedException();
            }

            public IPublicKey GetPublicKey()
            {
                throw new NotImplementedException();
            }

            public IBigInteger GetSerialNumber()
            {
                throw new NotImplementedException();
            }

            public IX500Name GetSubjectDN()
            {
                throw new NotImplementedException();
            }

            public byte[] GetTbsCertificate()
            {
                throw new NotImplementedException();
            }

            public void Verify(IPublicKey issuerPublicKey)
            {
                throw new NotImplementedException();
            }
        }
    }
}

