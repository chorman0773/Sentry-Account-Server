package gmail.chorman64.sentry.server.auth.servlet;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet implementation class RootServlet
 */
@WebServlet("/")
public class RootServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	public static final String response = "<html> "
			+ "<body>"
			+ "Hello"
			+ "</body>"
			+ "</html>";

    /**
     * @see HttpServlet#HttpServlet()
     */
    public RootServlet() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		response.setContentType("text/html");
		response.getWriter().append(RootServlet.response);
	}

}
