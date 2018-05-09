package gmail.chorman64.sentry.server.auth.session;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import javax.security.auth.Destroyable;
import javax.servlet.http.HttpServletRequest;

import org.apache.tomcat.util.codec.binary.Base64;

public class SessionToken implements Destroyable {
	private static final SecureRandom tokenRandom = new SecureRandom();
	private static final MessageDigest SHA256;
	public static final UUID NIL = new UUID(0,0);
	static {
		try {
			SHA256 = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
	private byte[] token;
	private UUID game;
	private Instant creationTime;
	private SentryAccount owner;
	private long permissions;
	private transient boolean destroyed;
	private transient Instant expiryTime;
	private static final Duration BASE_EXPERY_TIME = Duration.ofMinutes(15);
	private static final Duration REFRESH_TIME = Duration.ofMinutes(10);
	public SessionToken(SentryAccount owner,UUID game) {
		// TODO Auto-generated constructor stub
	}
	public SessionToken(SentryAccount owner,HttpServletRequest req) {

	}

	public SessionToken refresh(HttpServletRequest req) throws AuthenticationException {
		boolean tokenPassesGameCheck = false;
		byte[] accessToken  = Base64.decodeBase64(req.getHeader("Authentication"));
		UUID game = UUID.fromString(req.getHeader("Game"));
		if(this.game.equals(NIL))
			tokenPassesGameCheck = true;
		else if(game.equals(NIL))
			tokenPassesGameCheck = true;


	}

}
