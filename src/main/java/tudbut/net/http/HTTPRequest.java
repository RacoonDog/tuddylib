package tudbut.net.http;

import de.tudbut.io.StreamReader;
import de.tudbut.io.StreamWriter;
import de.tudbut.timer.AsyncTask;
import de.tudbut.type.Nothing;
import tudbut.obj.Partial;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;

public class HTTPRequest {
    private final ArrayList<HTTPHeader> headers = new ArrayList<>();
    private final String content;
    private final HTTPRequestType requestType;
    private final String path;
    private final String host;
    private final int port;
    private final boolean ssl;

    public HTTPRequest(HTTPRequestType requestType, String host, int port, String path, HTTPHeader... headers) {
        this(requestType, host, port, path, null, "", headers);
    }

    public HTTPRequest(HTTPRequestType requestTypeIn, String hostIn, int portIn, String pathIn, HTTPContentType type, String contentIn, HTTPHeader... headersIn) {
        ssl = hostIn.startsWith("https://");
        
        requestType = requestTypeIn;
        path = pathIn;
        host = hostIn;
        port = portIn;
        headers.add(new HTTPHeader("Host", ssl ? host.split("https://")[1] : host));
        if(!contentIn.equals("")) {
            headers.add(new HTTPHeader("Content-Type", type.asHeaderString));
            headers.add(new HTTPHeader("Content-Length", String.valueOf(contentIn.length())));
        }
        if(Arrays.stream(headersIn).noneMatch(httpHeader -> httpHeader.toString().startsWith("Connection: ")))
            headers.add(new HTTPHeader("Connection", "Close"));
        headers.addAll(Arrays.asList(headersIn));
        content = contentIn;
    }

    public String toString() {
        StringBuilder builder = new StringBuilder();

        builder.append(requestType.name()).append(" ").append(path).append(" HTTP/1.1\r\n");
        for (HTTPHeader header : headers) {
            builder.append(header.toString()).append("\r\n");
        }
        builder.append("\r\n");
        builder.append(content);
        
        return builder.toString();
    }

    public HTTPResponse send() throws IOException {
        Socket socket;
        if(ssl) {
            SSLSocket sslSocket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host.split("https://")[1], port);
            sslSocket.startHandshake();
            socket = sslSocket;
        }
        else
            socket = new Socket(InetAddress.getByName(host), port);
        StreamWriter writer = new StreamWriter(socket.getOutputStream());
        writer.writeChars(toString().toCharArray());
        return new HTTPResponse(new String(new StreamReader(socket.getInputStream()).readAllAsBytes()));
    }

    public Partial<HTTPResponse> sendKeepAlive() throws IOException {
        return sendKeepAlive(-1);
    }
    
    public Partial<HTTPResponse> sendKeepAlive(int timeout) throws IOException {
        Partial<HTTPResponse> partialResponse = new Partial<>(null);
        Socket socket;
        if (ssl) {
            SSLSocket sslSocket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host.split("https://")[1], port);
            sslSocket.startHandshake();
            socket = sslSocket;
        }
        else
            socket = new Socket(InetAddress.getByName(host), port);
        AsyncTask<Nothing> task = new AsyncTask<>(() -> {
            try {
                StreamWriter writer = new StreamWriter(socket.getOutputStream());
                writer.writeChars(toString().toCharArray());
                BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                String line;
                StringBuilder builder = new StringBuilder();
                while ((line = reader.readLine()) != null) {
                    builder.append(line).append("\n");
                    partialResponse.change(new HTTPResponse(builder.toString()));
                }
                socket.close();
                partialResponse.complete(partialResponse.get());
            } catch (Exception ignored) { }
            return null;
        });
        task.setTimeout(timeout);
        return partialResponse;
    }
}
