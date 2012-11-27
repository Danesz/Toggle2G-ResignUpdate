package com.mb.gui;

import java.awt.EventQueue;

import javax.swing.JFrame;

import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.filechooser.FileNameExtensionFilter;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;

import com.mb.resign.Resign;

import net.miginfocom.swing.MigLayout;
import javax.swing.JTextArea;
import javax.swing.JScrollPane;

public class ResignRomApplication
{

    private JFrame frmResignToolBy;
    private JTextField textField_ROM;
    private JTextField textField_keyapk;
    private JButton button; 

    /**
     * Launch the application.
     */
    public static void main(String[] args)
    {
        EventQueue.invokeLater(new Runnable()
        {
            public void run()
            {
                try
                {
                    ResignRomApplication window = new ResignRomApplication();
                    window.frmResignToolBy.setVisible(true);
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                }
            }
        });
    }

    /**
     * Create the application.
     */
    public ResignRomApplication()
    {
        initialize();
    }

    /**
     * Initialize the contents of the frame.
     */
    private void initialize()
    {
        frmResignToolBy = new JFrame();
        frmResignToolBy.setTitle("Resign Tool by The Master Baron");
        frmResignToolBy.setBounds(100, 100, 475, 347);
        frmResignToolBy.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frmResignToolBy.getContentPane().setLayout(new MigLayout("", "[59.00px][30.00][49px][13px][225.00px,grow][grow][]", "[23px][20px][][][grow]"));

        JLabel lblSourceRom = new JLabel("Source ROM:");
        frmResignToolBy.getContentPane().add(lblSourceRom, "cell 0 0,alignx left,aligny center");

        textField_ROM = new JTextField();
        textField_ROM.setEditable(false);
        frmResignToolBy.getContentPane().add(textField_ROM, "cell 1 0 5 1,growx,aligny center");
        textField_ROM.setColumns(10);

        textField_keyapk = new JTextField();
        frmResignToolBy.getContentPane().add(textField_keyapk, "cell 2 1 5 1,growx");
        textField_keyapk.setColumns(10);

        final JScrollPane scrollPane_con = new JScrollPane();
        frmResignToolBy.getContentPane().add(scrollPane_con, "cell 0 4 7 1,grow");

        final JTextArea textArea_con = new JTextArea();
        textArea_con.setEditable(false);
        scrollPane_con.setViewportView(textArea_con);

        final JButton btnResign = new JButton("Resign");
        btnResign.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                setLogPane(textArea_con);

                btnResign.setText("WORKING!");
                btnResign.setEnabled(false);
                button.setEnabled(false);
                textField_keyapk.setEditable(false);
                Thread thread = new Thread() { public void run() {
                    try
                    {
                        String keyapk = textField_keyapk.getText();
                        if ( keyapk != null && keyapk.trim().length() > 0 )
                        {
                            Resign.main(new String[] { textField_ROM.getText(), "-keyapk", keyapk });
                        }
                        else
                        {
                            Resign.main(new String[] { textField_ROM.getText() });
                        }
                    }
                    catch (Exception e1)
                    {
                        e1.printStackTrace();
                    }
                    frmResignToolBy.setEnabled(true);
                    btnResign.setText("Resign");
                    btnResign.setEnabled(true);
                    button.setEnabled(true);
                    textField_keyapk.setEditable(true);
                }; };
                
                thread.setDaemon(true);
                thread.start();
            }

        });
        btnResign.setEnabled(false);
        frmResignToolBy.getContentPane().add(btnResign, "cell 5 3 2 1,alignx right");

        button = new JButton("...");
        button.addActionListener(new ActionListener()
        {
            public void actionPerformed(ActionEvent e)
            {
                JFileChooser chooser = new JFileChooser();
                FileNameExtensionFilter filter = new FileNameExtensionFilter("ROM (*.zip)", "zip");
                chooser.setFileFilter(filter);
                int returnVal = chooser.showOpenDialog(button);
                if (returnVal == JFileChooser.APPROVE_OPTION)
                {
                    textField_ROM.setText(chooser.getSelectedFile().getPath());
                    btnResign.setEnabled(true);
                }
            }
        });
        frmResignToolBy.getContentPane().add(button, "cell 6 0,alignx right,aligny top");

        JLabel lblAdditionalCommandLine = new JLabel("-keyapk (Optional)");
        frmResignToolBy.getContentPane().add(lblAdditionalCommandLine, "cell 0 1 2 1,alignx left,aligny center");

    }

    private void setLogPane(final JTextArea textArea)
    {
        // Create a pair of Piped Streams.
        try
        {
            PipedInputStream pin = new PipedInputStream();
            PipedOutputStream pout = new PipedOutputStream(pin);
            final BufferedReader iis = new BufferedReader(new InputStreamReader(pin));
            PrintStream ps = new PrintStream(pout, true);
            System.setOut(ps);
            System.setErr(ps);

            // Construct and start a Thread to copy data from "is" to "os".
            Thread thread = new Thread("Console")
            {
                public void run()
                {
                    while(true)
                    {
                        try
                        {
                            Thread.sleep(100);
                            String line;
                            while ((line = iis.readLine()) != null)
                            {
                                textArea.append(line);
                                textArea.append("\n");
                                textArea.setCaretPosition(textArea.getDocument().getLength());
                            }
                        }
                        catch (Exception ex)
                        {
                            //textArea.append("*** Input or Output error ***\n" + ex.getMessage());
                            break;
                        }
                    }
                }
            };
            thread.setDaemon(true);
            thread.start();
        }
        catch (IOException e)
        {
            JOptionPane.showMessageDialog(null, "*** Input or Output error ***\n" + e, "Error", JOptionPane.ERROR_MESSAGE);
            e.printStackTrace();
        }
    }
}
