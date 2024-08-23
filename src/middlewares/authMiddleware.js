import { StatusCodes } from "http-status-codes";
import { JwtProvider } from "~/providers/JwtProvider";

const isAuthorized = async (req, res, next) => {
  //Cách 1:Lấy accessToken nằm trong request cookie phía client - withCredentials
  //trong file authorizeAxios và credentials trong CORS

  const accessTokenFromCookie = req.cookies?.accessToken;
  console.log("accessToken from cookie: ", accessTokenFromCookie);
  console.log("--------------------");

  if (!accessTokenFromCookie) {
    res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ message: "Authorization! (Token not found!)" });
    return;
  }

  //Cách 2:Lấy accessToken trong case FE lưu localstorage và gửi lên thông qua header authorization
  const accessTokenFromHeader = req.headers.authorization;
  console.log("accessToken from header: ", accessTokenFromHeader);
  console.log("--------------------");
  if (!accessTokenFromHeader) {
    res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ message: "Authorization! (Token not found!)" });
    return;
  }

  try {
    const accessTokenDecoded = await JwtProvider.verifyToken(
      accessTokenFromCookie,
      process.env.ACCESS_TOKEN_SECRET_SIGNATURE
    );

    req.jwtDecoded = accessTokenDecoded;
    next();
  } catch (error) {
    console.log("Error during token verification:", error);
    //TH 1: accessToken hết hạn
    if (error.message?.includes("jwt expired")) {
      res.status(StatusCodes.GONE).json({ message: "Need to refresh token!" });
      return;
    }
    // TH 2: nế như accessToken kh hợp lệ thì trả 401 cho FE xử lý logout
    res
      .status(StatusCodes.UNAUTHORIZED)
      .json({ message: "Token not found! Please login" });
  }
};

export const authMiddleware = {
  isAuthorized,
};
