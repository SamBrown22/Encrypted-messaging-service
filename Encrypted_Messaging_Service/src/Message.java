import java.io.Serializable;
import java.util.Date;

public class Message implements Serializable{
    private byte[] content;
    private Date timestamp;

    public Message(byte[] content, Date timestamp) {
        this.content = content;
        this.timestamp = timestamp;
    }

    public byte[] getContent() {
        return content;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    @Override
    public String toString() {
        return "Date: " + timestamp + "\nMessage: " + content;
    }
}
