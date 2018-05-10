package gmail.chorman64.sentry.server.auth.servlet;

import gmail.chorman64.sentry.server.auth.session.*;

@WebServlet("/server/accounts/*/*/*")
class FileRequestServlet extends HttpServlet{
  
  
  protected void doGet(HttpServletRequest req,HttpServletResponse rep){
    String requestPath = req.getRequestURI();
    String[] pathBuffer = requestPath.split("/");
    UUID user = UUID.fromString(pathBuffer[3]);
    UUID game = UUID.fromString(req.getHeader("Game"));
    SessionToken token = SessionToken.decode(req.getHeader("Session"));
    if(!token.isValid()){
      rep.getWriter().print("{\"reason\":\"Invalid Session\",\"reasoncode\":9}");
      rep.setStatus(401);
      rep.getWriter().flush();
     }else if(!token.validFor(game)){
      rep.getWriter().print("{\"reason\":\"Invalid Session\",\"reasoncode\":9}");
      rep.setStatus(401);
      rep.getWriter().flush();
     }else if(!token.isForUser(user)){
      rep.getWriter().print("{\"reason\":\"Outside of Authorization Scope\",\"reasoncode\":12}");
      rep.setStatus(403);
      rep.getWriter().flush();
     }else if(game.toString().equals("00000000-0000-0000-0000-000000000000")){
      if(!pathBuffer[4].equals("launcher")){
        rep.getWriter().print("{\"reason\":\"Outside of Game Scope\",\"reasoncode\":13}");
        rep.setStatus(403);
        rep.getWriter().flush();
      }else{
        rep.setStatus(200);
        token.getUser().getFile(requestPath.substring(55)).writeTo(rep.getOutputStream());
        rep.getOutputStream().flush();
      }
     }
      
  }

}
