#
# This R language script finds a degree 2 interpolating polynomial for f =
# log2(x) over the interval [1, 2).
#

f = function(x) { log2(x) }

get.chebyshev.points = function(a, b, n)
{
    (a+b)/2 + (b-a)/2 * cos(((2*(1:n)-1)*pi)/(2*n))
}

build.vandermonde.matrix = function(x)
{
    n = length(x)
    V = matrix(nrow=n, ncol=n)
    for (j in 1:n)
        V[,j] = x^(j-1)
    return(V)
}

evaluate.polynomial = function(coeffs, x)
{
    y = coeffs[length(coeffs)]
    for (i in (length(coeffs)-1):1)
        y = y*x + coeffs[i]
    return(y)
}

x.plot = seq(1, 2, length=1000)
x.chebychev = get.chebyshev.points(1, 2, 3)
V = build.vandermonde.matrix(x.chebychev)
coeffs.a = solve(V, f(x.chebychev))
coeffs.a = c(coeffs.a)
polynomial.interp = function(x) { evaluate.polynomial(coeffs.a, x) }
cat("Coefficients of degree 2 interpolating polynomial:\n")
options(digits=10)
cat(coeffs.a, "\n")
pdf("polynomial-interp.pdf")
plot(x.plot, f(x.plot), col="black", type="l", xlab="x", ylab="y",
	 main="f(x) and interpolating polynomial approximation")
points(x.chebychev, f(x.chebychev), pch=19, col="red")
lines(x.plot, polynomial.interp(x.plot), col="blue")
legend("topleft", pch=c(NA, NA, 19),
	   col=c("black", "blue", "red"), lty=c(1,1,0),
       legend=c("f(x)", "Interpolating polynomial", "Chebychev points"),
       inset=0.07)
