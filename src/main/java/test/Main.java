package test;

import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEUtil;

import javax.mail.*;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.search.FlagTerm;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Properties;

// http://stackoverflow.com/questions/11079848/reading-encrypted-email

public class Main {

    public static void main(String[] args) throws Throwable {
        final String musername = "mail_username";
        final String mpassword = "mail_password";

        Properties props = new Properties();
        props.setProperty("mail.store.protocol", "imaps");

        Session session = Session.getInstance(props, null);

        Store store = session.getStore();
        store.connect("imap.gmail.com", musername, mpassword);
        Folder inbox = store.getFolder("INBOX");
        inbox.open(Folder.READ_ONLY);
        Flags seen = new Flags(Flags.Flag.SEEN);
        FlagTerm unseenFlagTerm = new FlagTerm(seen, false);
        Message messages[] = inbox.search(unseenFlagTerm);

        System.out.println("Antal ulæste mails: " + messages.length);

        AsymmetricKeyPair keyPair = getKeyPair();
        RSAPrivateKey privateKey = keyPair.privateKey;
        X509Certificate cert = keyPair.certificate;

        for (Message message : messages) {

            JceKeyTransRecipientId recId = new JceKeyTransRecipientId(cert);

            SMIMEEnveloped m = new SMIMEEnveloped((MimeMessage) message);
            RecipientInformationStore recipients = m.getRecipientInfos();
            RecipientInformation recipient = recipients.get(recId);
            JceKeyTransRecipient pKeyRecp = new JceKeyTransEnvelopedRecipient(privateKey);

            MimeBodyPart res = SMIMEUtil.toMimeBodyPart(recipient.getContent(pKeyRecp));
            MimeMultipart parts = (MimeMultipart) res.getContent();

            /*for (Enumeration<Header> e = res.getAllHeaders(); e.hasMoreElements();) {
                Header h = e.nextElement();
                System.out.println(h.getName() + ": " + h.getValue());
            }*/
            System.out.println("Subject: " + message.getSubject());
            for (Address a : message.getFrom()) {
                System.out.println("From: " + a.toString());
            }
            for (int i = 0; i < parts.getCount(); i++) {
                BodyPart part = parts.getBodyPart(i);
                if (part.getContentType().contains("text/plain")) {
                    System.out.println(part.getContent());
                }
            }
        }
    }

    private static AsymmetricKeyPair getKeyPair() throws Throwable {
        String pfxPassword = "cert_password";
        KeyStore ks = null;
        ks = KeyStore.getInstance("pkcs12", "SunJSSE");
        ks.load(new FileInputStream("/pathToCertificate.p12"), pfxPassword.toCharArray());
        String a = ks.aliases().nextElement();
        RSAPrivateKey privateKey = (RSAPrivateKey) ks.getKey(a, pfxPassword.toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate(a);
        return new AsymmetricKeyPair(privateKey, cert);
    }

}

class AsymmetricKeyPair {
    public final RSAPrivateKey privateKey;
    public final X509Certificate certificate;

    public AsymmetricKeyPair(RSAPrivateKey privateKey, X509Certificate certificate) {
        this.privateKey = privateKey;
        this.certificate = certificate;
    }
}