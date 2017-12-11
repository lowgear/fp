using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using ResultOf;

namespace FileSenderRailway
{
    public class FileSender
    {
        public static IEnumerable<Result<FileContent>> SendFiles(FileContent[] files, X509Certificate certificate,
            ISender sender, IRecognizer recognizer, ICryptographer cryptographer, Func<DateTime> now)
        {
            foreach (var file in files)
            {
                var doc = PrepareFileToSend(file, certificate, recognizer, cryptographer, now);
                if (!doc.IsSuccess)
                    yield return Result.Fail<FileContent>(doc.Error);
                else
                {
                    sender.Send(doc.Value); //Can't send. 
                    yield return Result.Ok(file);
                }
            }
        }

        private static Result<Document> PrepareFileToSend(FileContent file, X509Certificate certificate,
            IRecognizer recognizer, ICryptographer cryptographer, Func<DateTime> now)
        {
            var doc = recognizer.Recognize(file);
            if (!IsValidFormatVersion(doc))
                return Result.Fail<Document>($"Can't prepare file to send. Invalid format version {doc.Format}");
            if (!IsValidTimestamp(doc, now))
                return Result.Fail<Document>($"Can't prepare file to send. Too old document {doc.CreationDate}");
            doc = doc.SetContent(cryptographer.Sign(doc.Content, certificate));
            return doc;
        }

        private static bool IsValidFormatVersion(Document doc)
        {
            return doc.Format == "4.0" || doc.Format == "3.1";
        }

        private static bool IsValidTimestamp(Document doc, Func<DateTime> now)
        {
            var oneMonthBefore = now().AddMonths(-1);
            return doc.CreationDate > oneMonthBefore;
        }
    }
}
