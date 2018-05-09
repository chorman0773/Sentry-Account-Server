package gmail.chorman64.sentry.server.auth.session;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.UUID;

import javax.mail.internet.InternetAddress;

public class SentryAccount {
	private UUID id;
	private UUID currGame;
	private SessionToken currSession;
	private byte[] accessToken;
	private Instant lastAccountAccess;
	private InternetAddress assignedAccountAddress;
	private static final Duration MIN_ACCESS_TIME = Duration.of(1, ChronoUnit.HOURS);
	private static final SecureRandom tokenRand = new SecureRandom();

	private static byte[] toBytes(UUID id) {
		byte[] b = new byte[16];
		long high = id.getMostSignificantBits();
		long low = id.getLeastSignificantBits();
		b[0] =  (byte) (high>>>56);
		b[1] =  (byte) (high>>>48);
		b[2] =  (byte) (high>>>40);
		b[3] =  (byte) (high>>>32);
		b[4] =  (byte) (high>>>24);
		b[5] =  (byte) (high>>>16);
		b[6] =  (byte) (high>>> 8);
		b[7] =  (byte) (high     );
		b[8] =  (byte) (low>>> 56);
		b[9] =  (byte) (low>>> 48);
		b[10] = (byte) (low>>> 40);
		b[11] = (byte) (low>>> 32);
		b[12] = (byte) (low>>> 24);
		b[13] = (byte) (low>>> 16);
		b[14] = (byte) (low>>>  8);
		b[15] = (byte) (low      );
		return b;
	}
	private static UUID fromBytes(byte[] b) {
		long high, low;
		high = b[0]<<56L | b[1]<<48L | b[2]<<40L | b[3]<<32L
				| b[4]<<24L | b[5] <<16L | b[6]<<8L | b[7];
		low = b[8]<<56L | b[9]<<48L | b[10]<<40L | b[11]<<32L
				| b[12]<<24L | b[13] <<16L | b[14]<<8L | b[15];
		return new UUID(high,low);
	}

	public SentryAccount() {
		// TODO Auto-generated constructor stub
	}
	/**
	 * @return the id
	 */
	public UUID getId() {
		return id;
	}
	public boolean hasAccessExpired() {
		return Instant.now().isAfter(lastAccountAccess.plus(MIN_ACCESS_TIME));
	}
	public boolean validateAccess(byte[] accessToken) {
		return Arrays.equals(accessToken, this.accessToken)&hasAccessExpired();
	}

	public byte[] genAccessToken() {
		byte[] token = new byte[64];
		tokenRand.nextBytes(token);
		byte[] uuid = toBytes(id);
		this.accessToken = new byte[80];
		System.arraycopy(this.accessToken, 0, token, 0, 64);
		System.arraycopy(this.accessToken, 64, uuid, 0, 16);
		return this.accessToken;
	}

}
