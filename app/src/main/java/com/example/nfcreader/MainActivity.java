package com.example.nfcreader;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NdefMessage;
import android.nfc.NfcAdapter;
import android.nfc.NfcManager;
import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.nfc.tech.NfcA;
import android.os.Bundle;

import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.snackbar.Snackbar;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import android.os.Parcelable;
import android.util.Log;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;

import java.io.IOException;
import java.lang.reflect.Array;
import java.util.ArrayList;

import static android.nfc.NfcAdapter.getDefaultAdapter;

/**
 * foreground dispatch code copied from
 * https://code.tutsplus.com/tutorials/reading-nfc-tags-with-android--mobile-17278
 *
 */

public class MainActivity extends AppCompatActivity {

    private static final String MIME_TEXT_PLAIN = "text/plain";
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private static final int secretSector = 3;  // we store our super secret message in sector 3
    private static final byte[] superSecretKeyA = hexStringToByteArray("ad03df21dfe6");

    private IntentFilter filterList[];
    private String techList[][];
    private ArrayList<String> knownUIDs;

    private NfcAdapter nfcAdapter;

    private TextView text;
    private ListView list;
    private ArrayList<String> listItems;
    private ArrayAdapter arrayAdapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        text = (TextView) findViewById(R.id.Text);
        list = (ListView) findViewById(R.id.List);

        listItems = new ArrayList<>();
        arrayAdapter = new ArrayAdapter(this, android.R.layout.simple_list_item_1, listItems);
        list.setAdapter(arrayAdapter);
        NfcManager manager = (NfcManager) this.getSystemService(Context.NFC_SERVICE);
        nfcAdapter = manager.getDefaultAdapter();

        // list of intents that we want to filter for
        IntentFilter tech = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);
        IntentFilter ndef = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
        IntentFilter tag = new IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED);
        filterList = new IntentFilter[] {tech, ndef, tag};
        techList = new String[][] {new String[] {MifareClassic.class.getName()}};

        // check if NFC is supported or on
        if(nfcAdapter == null) {
            text.setText(R.string.no_nfc);
        }

        // add a list of registered UIDs
        knownUIDs = new ArrayList<>();
        knownUIDs.add("26AFE190");

    }

    @Override
    protected void onNewIntent(Intent intent) {
        readIntent(intent);
    }

    @Override
    protected void onResume() {
        super.onResume();
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
        nfcAdapter.enableForegroundDispatch(this, pendingIntent, filterList, techList);
    }

    @Override
    protected void onPause() {
        super.onPause();
        nfcAdapter.disableForegroundDispatch(this);
    }

    private void readIntent(final Intent intent) {
        String action = intent.getAction();
        // check that its the intents that we want
        if (action.equals(NfcAdapter.ACTION_TAG_DISCOVERED)
                || action.equals(NfcAdapter.ACTION_NDEF_DISCOVERED)
                || action.equals(NfcAdapter.ACTION_TECH_DISCOVERED)) {

            // apparently mfc.connect needs to be run not on main?
            Runnable task = new Runnable() {
                @Override
                public void run() {
                    Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                    MifareClassic mfc = MifareClassic.get(tag);
                    // if RFID tag is not mifare classic, exit
                    if (mfc == null) return;
                    byte[] uid = tag.getId();
                    String uidInHex = bitsToHex(uid);
                    Boolean UIDregistered = false;
                    if(knownUIDs.contains(uidInHex)) UIDregistered = true;
                    listItems.add(uidInHex);

                    try {
                        mfc.connect();
                        if(mfc.isConnected()) {
                            boolean authenticate = mfc.authenticateSectorWithKeyA(secretSector, superSecretKeyA);
                            if (authenticate && UIDregistered) {
                                byte[] data = mfc.readBlock(0 + mfc.sectorToBlock(secretSector));
                                String payload = new String(data, "UTF-8");
                                text.setText("UID = " + uidInHex + "\nSecret Message:\n" + payload);
                            } else if(UIDregistered && !authenticate){
                                text.setText("Hey, wrong key buddy!");
                            } else if(!UIDregistered && authenticate) {
                                text.setText("I don't know you... how do you know my key?!");
                            } else {
                                text.setText("Get outta here ya hooligan!");
                            }
                            mfc.close();
                        }
                    } catch (IOException e) {
                        text.setText("IO Exception");
                        e.printStackTrace();
                    }
                }
            };
            task.run();
        }
    }

    private String bitsToHex(byte[] bits) {
        char[] hexChars = new char[bits.length * 2];
        for (int i = 0; i < bits.length; i++) {
            int v = bits[i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
