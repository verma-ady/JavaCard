/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package Encrpyt;

import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

/**
 *
 * @author Mukesh
 */
public class Encrypt extends Applet {

    OwnerPIN ownerPin = new OwnerPIN((byte)3, (byte)2);//max try, size of pin
    AESKey myKey;
    
    public static final byte E_CLA = (byte) 0xA1;
    public static final byte E_SET_OWNER_PIN = (byte) 0xB1;
    public static final byte E_ENCRYPT_D = (byte) 0xB2;
    public static final byte E_INP_D = (byte) 0xB3;
    public static final byte E_OUT_D = (byte) 0xB4;
    boolean isSet = false;
    private Cipher symCipher;
    short data = (short) 0;
    
    /**
     * Installs this applet.
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Encrypt();
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected Encrypt() {
        symCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false); 
        myKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
        register();
    }

    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    public void process(APDU apdu) {
        byte [] buffer=apdu.getBuffer();
        if(buffer[ISO7816.OFFSET_CLA]!=E_CLA)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        
        switch(buffer[ISO7816.OFFSET_INS]){
            case E_SET_OWNER_PIN:
                apdu.setIncomingAndReceive();
                byte pin[] = new byte[2];
                Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, pin, (short)0, (short)2 );
                ownerPin.update(pin, (short)0, (byte)2);
                isSet = true;
                break;
            case E_INP_D:
                if(!isSet) 
                    ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                
                apdu.setIncomingAndReceive();
                if(!ownerPin.check(buffer ,ISO7816.OFFSET_P1, (byte)2)) 
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                
                data = Util.getShort(buffer, ISO7816.OFFSET_CDATA );
                break;
            case E_OUT_D:
                if(!isSet) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                
                //apdu.setIncomingAndReceive();
                if(!ownerPin.check(buffer ,ISO7816.OFFSET_P1, (byte)2)) 
                    ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                
                Util.setShort(buffer, (short)0, data);
                apdu.setOutgoingAndSend((short)0, (short)2);
                break;
            case E_ENCRYPT_D: 
                RandomData randomData = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
                byte[] random = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_RESET);
                randomData.generateData(random, (short)0, (short)random.length);
                myKey.setKey(random, (short)0);

                if(!isSet) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                symCipher.init(myKey, Cipher.MODE_ENCRYPT);
                
                byte[] dataB = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 
                                0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
                
                
                short le = apdu.setOutgoing();

                if(!myKey.isInitialized())
                        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                
                try{
                    if( le != symCipher.doFinal(dataB, (short)0, (short)dataB.length, buffer, (short)0))
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                } catch(Exception exception ) {
//                    ISOException.throwIt(exception.getReason());
                    ISOException.throwIt((short)16);
                }
                apdu.setOutgoingLength(le);
                apdu.sendBytes((short)0, le);
//                ISOException.throwIt((short)32);
                break;
            default : ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }//switch
    }//process
}
