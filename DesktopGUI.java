import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class Desktop_GUI extends JFrame{


    public static void main(String[] args){
        Desktop_GUI desk_gui = new Desktop_GUI("test", new Dimension(800, 600));
    }

    private Desktop_GUI(String title, Dimension size) {
        JFrame frame = mainFrame(title, size);
    }

    private JFrame mainFrame(String title, Dimension size){
        JFrame frame = new JFrame(title);

        frame.setPreferredSize(size);
        frame.setSize(800, 600);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setVisible(true);
        frame.setBackground(Color.darkGray);
        frame.getContentPane().setLayout(new GridBagLayout());
        //need to alter gridbag before
//      frame.getContentPane().add(mainPanel(new Dimension(600, 400)), new Grid);

        frame.add(chatter(new Dimension(800, 600)));


        frame.pack();

        return frame;
    }


    private JPanel chatter(Dimension sizeScale){

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(15,15,15,15);

        JPanel chatroom = new JPanel(new GridBagLayout());

        chatroom.setPreferredSize(sizeScale);
        chatroom.setLocation(300, 300);

        JLabel chatBubble = new JLabel("      ");
        JTextArea textArea = new JTextArea("asdasdfarea");
        JButton submitButton = new JButton("Submit");

        submitButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                chatBubble.setText(textArea.getText());
            }
        });
        gbc.gridx = 0;
        gbc.gridy = 2;
        chatroom.add(submitButton, gbc);
        gbc.gridx = 0;
        gbc.gridy = 1;
        chatroom.add(chatBubble  , gbc);
        gbc.gridx = 0;
        gbc.gridy = 0;
        chatroom.add(textArea    , gbc);


        return chatroom;
    }


    private JPanel mainPanel(Dimension frame){
        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.add(chatter(frame));
        return mainPanel;
    }
}
