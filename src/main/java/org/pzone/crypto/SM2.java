package org.pzone.crypto;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * SM2公钥加密算法实现 包括 -签名,验签 -密钥交换 -公钥加密,私钥解密
 * @author Potato
 */
public class SM2 {
	private static final BigInteger n = new BigInteger(
			"FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "7203DF6B" + "21C6052B" + "53BBF409" + "39D54123", 16);
	private static final BigInteger p = new BigInteger(
			"FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "00000000" + "FFFFFFFF" + "FFFFFFFF", 16);
	private static final BigInteger a = new BigInteger(
			"FFFFFFFE" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "FFFFFFFF" + "00000000" + "FFFFFFFF" + "FFFFFFFC", 16);
	private static final BigInteger b = new BigInteger(
			"28E9FA9E" + "9D9F5E34" + "4D5A9E4B" + "CF6509A7" + "F39789F5" + "15AB8F92" + "DDBCBD41" + "4D940E93", 16);
	private static final BigInteger gx = new BigInteger(
			"32C4AE2C" + "1F198119" + "5F990446" + "6A39C994" + "8FE30BBF" + "F2660BE1" + "715A4589" + "334C74C7", 16);
	private static final BigInteger gy = new BigInteger(
			"BC3736A2" + "F4F6779C" + "59BDCEE3" + "6B692153" + "D0A9877C" + "C62A4740" + "02DF32E5" + "2139F0A0", 16);
	private static ECDomainParameters ecc_bc_spec;
	private static final int DIGEST_LENGTH = 32;

	private static final SecureRandom random = new SecureRandom();
	private static ECCurve.Fp curve;
	private static ECPoint G;

	/**
	 * 随机数生成器
	 *
	 */
	private static BigInteger random(BigInteger max) {

		BigInteger r = new BigInteger(256, random);
		// int count = 1;

		while (r.compareTo(max) >= 0) {
			r = new BigInteger(128, random);
			// count++;
		}

		// System.out.println("count: " + count);
		return r;
	}

	/**
	 * 判断字节数组是否全0
	 *
	 */
	private boolean allZero(byte[] buffer) {
		for (byte value : buffer) {
			if (value != 0)
				return false;
		}
		return true;
	}

	/**
	 * 公钥加密
	 * 
	 * @param input
	 *            加密原文
	 * @param publicKey
	 *            公钥
	 */
	public byte[] encrypt(String input, ECPoint publicKey) {

		byte[] inputBuffer = input.getBytes();

		byte[] C1Buffer;
		ECPoint kpb;
		byte[] t;
		do {
			/* 1 产生随机数k，k属于[1, n-1] */
			BigInteger k = random(n);

			/* 2 计算椭圆曲线点C1 = [k]G = (x1, y1) */
			ECPoint C1 = G.multiply(k);
			C1Buffer = C1.getEncoded(false);

			/*
			 * 3 计算椭圆曲线点 S = [h]Pb
			 */
			BigInteger h = ecc_bc_spec.getH();
			if (h != null) {
				ECPoint S = publicKey.multiply(h);
				if (S.isInfinity())
					throw new IllegalStateException();
			}

			/* 4 计算 [k]PB = (x2, y2) */
			kpb = publicKey.multiply(k).normalize();

			/* 5 计算 t = KDF(x2||y2, klen) */
			byte[] kpbBytes = kpb.getEncoded(false);
			t = KDF(kpbBytes, inputBuffer.length);
		} while (allZero(t != null ? t : new byte[0]));

		/* 6 计算C2=M^t */
		byte[] C2 = new byte[inputBuffer.length];
		for (int i = 0; i < inputBuffer.length; i++) {
			if (t != null) {
				C2[i] = (byte) (inputBuffer[i] ^ t[i]);
			}
		}

		/* 7 计算C3 = Hash(x2 || M || y2) */
		byte[] C3 = sm3hash(kpb.getXCoord().toBigInteger().toByteArray(), inputBuffer,
				kpb.getYCoord().toBigInteger().toByteArray());

		/* 8 输出密文 C=C1 || C2 || C3 */

		byte[] encryptResult = new byte[C1Buffer.length + C2.length + C3.length];

		System.arraycopy(C1Buffer, 0, encryptResult, 0, C1Buffer.length);
		System.arraycopy(C2, 0, encryptResult, C1Buffer.length, C2.length);
		System.arraycopy(C3, 0, encryptResult, C1Buffer.length + C2.length, C3.length);

		return encryptResult;
	}

	/**
	 * 私钥解密
	 * 
	 * @param encryptData
	 *            密文数据字节数组
	 * @param privateKey
	 *            解密私钥
	 */
	public String decrypt(byte[] encryptData, BigInteger privateKey) {

		byte[] C1Byte = new byte[65];
		System.arraycopy(encryptData, 0, C1Byte, 0, C1Byte.length);

		ECPoint C1 = curve.decodePoint(C1Byte).normalize();

		/* 计算椭圆曲线点 S = [h]C1 是否为无穷点 */
		BigInteger h = ecc_bc_spec.getH();
		if (h != null) {
			ECPoint S = C1.multiply(h);
			if (S.isInfinity())
				throw new IllegalStateException();
		}
		/* 计算[dB]C1 = (x2, y2) */
		ECPoint dBC1 = C1.multiply(privateKey).normalize();

		/* 计算t = KDF(x2 || y2, klen) */
		byte[] dBC1Bytes = dBC1.getEncoded(false);
		int klen = encryptData.length - 65 - DIGEST_LENGTH;
		byte[] t = KDF(dBC1Bytes, klen);

		assert t != null;
		if (allZero(t)) {
			System.err.println("all zero");
			throw new IllegalStateException();
		}

		/* 5 计算M'=C2^t */
		byte[] M = new byte[klen];
		for (int i = 0; i < M.length; i++) {
			M[i] = (byte) (encryptData[C1Byte.length + i] ^ t[i]);
		}

		/* 6 计算 u = Hash(x2 || M' || y2) 判断 u == C3是否成立 */
		byte[] C3 = new byte[DIGEST_LENGTH];

		System.arraycopy(encryptData, encryptData.length - DIGEST_LENGTH, C3, 0, DIGEST_LENGTH);
		byte[] u = sm3hash(dBC1.getXCoord().toBigInteger().toByteArray(), M,
				dBC1.getYCoord().toBigInteger().toByteArray());
		if (Arrays.equals(u, C3)) {
			return new String(M, StandardCharsets.UTF_8);
		}
		return null;

	}

	/**
	 * 判断是否在范围内
	 *
	 */
	private boolean between(BigInteger param, BigInteger min) {
		return param.compareTo(min) >= 0 && param.compareTo(SM2.p) < 0;
	}

	/**
	 * 判断生成的公钥是否合法
	 *
	 */
	private boolean checkPublicKey(ECPoint publicKey) {

		if (!publicKey.isInfinity()) {

			BigInteger x = publicKey.getXCoord().toBigInteger();
			BigInteger y = publicKey.getYCoord().toBigInteger();

			if (between(x, new BigInteger("0")) && between(y, new BigInteger("0"))) {

				BigInteger xResult = x.pow(3).add(a.multiply(x)).add(b).mod(p);

				BigInteger yResult = y.pow(2).mod(p);

				return yResult.equals(xResult) && publicKey.multiply(n).isInfinity();
			}
		}
		return false;
	}

	/**
	 * 生成密钥对
	 *
	 */
	public SM2KeyPair generateKeyPair() {
		SM2KeyPair keyPair;
		while (true) {
			BigInteger d = random(n.subtract(new BigInteger("1")));
			ECPoint ecPoint = G.multiply(d).normalize();
			keyPair = new SM2KeyPair(ecPoint, d);
			if (bytesToHex(d.toByteArray()).length() == 64) {
				if (bytesToHex(ecPoint.getXCoord().toBigInteger().toByteArray()).length() == 64 && bytesToHex(ecPoint.getYCoord().toBigInteger().toByteArray()).length() == 64 && (ecPoint.getXCoord().toString() + ecPoint.getYCoord().toString()).length() == 128) {
					break;
				}
			}
		}
		if (checkPublicKey(keyPair.getPublicKey())) {
			return keyPair;
		} else {
			return null;
		}
	}

	public SM2() {
		curve = new ECCurve.Fp(p, // q
				a, // a
				b); // b
		G = curve.createPoint(gx, gy);
		ecc_bc_spec = new ECDomainParameters(curve, G, n);
	}

	/**
	 * 字节数组拼接
	 *
	 */
	private static byte[] join(byte[]... params) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] res = null;
		try {
			for (byte[] param : params) {
				baos.write(param);
			}
			res = baos.toByteArray();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return res;
	}

	/**
	 * sm3摘要
	 *
	 */
	private static byte[] sm3hash(byte[]... params) {
		byte[] res = null;
		try {
			res = SM3.hash(join(params));
		} catch (IOException e) {
			e.printStackTrace();
		}
		return res;
	}

	/**
	 * 密钥派生函数
	 * 
	 * @param klen
	 *            生成klen字节数长度的密钥
	 */
	private static byte[] KDF(byte[] Z, int klen) {
		int ct = 1;
		int end = (int) Math.ceil(klen * 1.0 / 32);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			for (int i = 1; i < end; i++) {
				baos.write(sm3hash(Z, SM3.toByteArray(ct)));
				ct++;
			}
			byte[] last = sm3hash(Z, SM3.toByteArray(ct));
			if (klen % 32 == 0) {
				baos.write(last);
			} else
				baos.write(last, 0, klen % 32);
			return baos.toByteArray();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}


	/**
	 * 比特数组转字符串
	 * @param bytes 比特数组
	 * @return 字符串
	 */
	public static String bytesToHex(byte[] bytes) {
		final byte[] HEX_ARRAY = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
		byte[] hexChars = new byte[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = HEX_ARRAY[v >>> 4];
			hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
		}
		return new String(hexChars, StandardCharsets.UTF_8);
	}

	/**
	 * 十六进制数字字符串转椭圆曲线点
	 * @param hex 十六进制数字字符串
	 * @return 椭圆曲线点
	 */
	public static ECPoint hexToECPoint(String hex) {
		String xString = hex.substring(0, 64);
		String yString = hex.substring(64);
		byte[] x_byte = hexStringToByteArray(xString);
		BigInteger x_biginteger = new BigInteger(x_byte);
		byte[] y_byte = hexStringToByteArray(yString);
		BigInteger y_biginteger = new BigInteger(y_byte);
		return curve.createPoint(x_biginteger, y_biginteger);
	}

	/**
	 * 字符串转比特数组
	 * @param s 字符串
	 * @return 比特数组
	 */
	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}
}
