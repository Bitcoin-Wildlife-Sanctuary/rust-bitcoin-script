use bitcoin::{blockdata::opcodes::Opcode, opcodes::all::OP_RESERVED};
use proc_macro2::{
    Delimiter, Span, TokenStream,
    TokenTree::{self, *},
};
use quote::quote;
use std::iter::Peekable;
use std::str::FromStr;

#[derive(Debug)]
pub enum Syntax {
    Opcode(Opcode),
    Escape(TokenStream),
    Bytes(Vec<u8>),
    Int(i64),
}

macro_rules! emit_error {
    ($span:expr, $($message:expr),*) => {{
        #[cfg(not(test))]
        proc_macro_error::emit_error!($span, $($message),*);

        #[cfg(test)]
        panic!($($message),*);

        #[allow(unreachable_code)]
        {
            panic!();
        }
    }}
}

macro_rules! abort {
    ($span:expr, $($message:expr),*) => {{
        #[cfg(not(test))]
        proc_macro_error::abort!($span, $($message),*);

        #[cfg(test)]
        panic!($($message),*);
    }}
}

pub fn parse(tokens: TokenStream) -> Vec<(Syntax, Span)> {
    let mut tokens = tokens.into_iter().peekable();
    let mut syntax = Vec::with_capacity(2048);

    while let Some(token) = tokens.next() {
        let token_str = token.to_string();
        syntax.push(match (&token, token_str.as_ref()) {
            // Wrap for loops such that they return a Vec<ScriptBuf>
            (Ident(_), ident_str) if ident_str == "for" => parse_for_loop(token, &mut tokens),
            // Wrap if-else statements such that they return a Vec<ScriptBuf>
            (Ident(_), ident_str) if ident_str == "if" => parse_if(token, &mut tokens),
            // Replace DEBUG with OP_RESERVED
            (Ident(_), ident_str) if ident_str == "DEBUG" => {
                (Syntax::Opcode(OP_RESERVED), token.span())
            }

            // identifier, look up opcode
            (Ident(_), _) => {
                match opcode_from_str(&token_str) {
                    Ok(opcode) => (Syntax::Opcode(opcode), token.span()),
                    // Not a native Bitcoin opcode
                    // Allow functions without arguments to be identified by just their name
                    _ => {
                        let span = token.span();
                        let mut pseudo_stream = TokenStream::from(token);
                        pseudo_stream.extend(TokenStream::from_str("()"));
                        (Syntax::Escape(pseudo_stream), span)
                    }
                }
            }

            (Group(inner), _) => {
                let escape = TokenStream::from(inner.stream().clone());
                (Syntax::Escape(escape), token.span())
            }

            // '<', start of escape (parse until first '>')
            (Punct(_), "<") => parse_escape(token, &mut tokens),

            // '~' start of escape (parse until the next '~') ignores '<' and '>'
            (Punct(_), "~") => parse_escape_extra(token, &mut tokens),

            // literal, push data (int or bytes)
            (Literal(_), _) => parse_data(token),

            // negative sign, parse negative int
            (Punct(_), "-") => parse_negative_int(token, &mut tokens),

            // anything else is invalid
            _ => abort!(token.span(), "unexpected token"),
        });
    }
    syntax
}

fn parse_if<T>(token: TokenTree, tokens: &mut Peekable<T>) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    // Use a Vec here to get rid of warnings when the variable is overwritten
    let mut escape = quote! {
        let mut script_var = Vec::with_capacity(256);
    };
    escape.extend(std::iter::once(token.clone()));

    while let Some(if_token) = tokens.next() {
        match if_token {
            Group(block) if block.delimiter() == Delimiter::Brace => {
                let inner_block = block.stream();
                escape.extend(quote! {
                    {
                        script_var.extend_from_slice(script! {
                            #inner_block
                        }.as_bytes());
                    }
                });

                match tokens.peek() {
                    Some(else_token) if else_token.to_string().as_str() == "else" => continue,
                    _ => break,
                }
            }
            _ => {
                escape.extend(std::iter::once(if_token));
                continue;
            }
        };
    }
    escape = quote! {
        {
            #escape;
            bitcoin::script::ScriptBuf::from(script_var)
        }
    }
    .into();
    (Syntax::Escape(escape), token.span())
}

fn parse_for_loop<T>(token: TokenTree, tokens: &mut T) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    let mut escape = quote! {
        let mut script_var = vec![];
    };
    escape.extend(std::iter::once(token.clone()));

    while let Some(for_token) = tokens.next() {
        match for_token {
            Group(block) if block.delimiter() == Delimiter::Brace => {
                let inner_block = block.stream();
                escape.extend(quote! {
                    {
                        let next_script = script !{
                            #inner_block
                        };
                        script_var.extend_from_slice(next_script.as_bytes());
                    }
                    bitcoin::script::ScriptBuf::from(script_var)
                });
                break;
            }
            _ => {
                escape.extend(std::iter::once(for_token));
                continue;
            }
        };
    }

    (Syntax::Escape(quote! { { #escape } }.into()), token.span())
}

fn parse_escape<T>(token: TokenTree, tokens: &mut T) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    let mut escape = TokenStream::new();
    let mut span = token.span();

    loop {
        let token = tokens
            .next()
            .unwrap_or_else(|| abort!(token.span(), "unterminated escape"));
        let token_str = token.to_string();

        span = span.join(token.span()).unwrap_or(token.span());

        // end of escape
        if let (Punct(_), ">") = (&token, token_str.as_ref()) {
            break;
        }

        escape.extend(TokenStream::from(token));
    }

    (Syntax::Escape(escape), span)
}

fn parse_escape_extra<T>(token: TokenTree, tokens: &mut T) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    let mut escape = TokenStream::new();
    let mut span = token.span();

    loop {
        let token = tokens
            .next()
            .unwrap_or_else(|| abort!(token.span(), "unterminated escape"));
        let token_str = token.to_string();

        span = span.join(token.span()).unwrap_or(token.span());

        // end of escape
        if let (Punct(_), "~") = (&token, token_str.as_ref()) {
            break;
        }

        escape.extend(TokenStream::from(token));
    }

    (Syntax::Escape(escape), span)
}

fn parse_data(token: TokenTree) -> (Syntax, Span) {
    if token.to_string().starts_with("0x") {
        if token
            .to_string()
            .strip_prefix("0x")
            .unwrap_or_else(|| unreachable!())
            .trim_start_matches('0')
            .len()
            <= 8
        {
            parse_hex_int(token)
        } else {
            parse_bytes(token)
        }
    } else {
        parse_int(token, false)
    }
}

fn parse_bytes(token: TokenTree) -> (Syntax, Span) {
    let hex_bytes = &token.to_string()[2..];
    let bytes = hex::decode(hex_bytes).unwrap_or_else(|err| {
        emit_error!(token.span(), "invalid hex literal ({})", err);
    });
    (Syntax::Bytes(bytes), token.span())
}

fn parse_hex_int(token: TokenTree) -> (Syntax, Span) {
    let token_str = &token.to_string()[2..];
    let n: u32 = u32::from_str_radix(token_str, 16).unwrap_or_else(|err| {
        emit_error!(token.span(), "invalid hex string ({})", err);
    });
    (Syntax::Int(n as i64), token.span())
}

fn parse_int(token: TokenTree, negative: bool) -> (Syntax, Span) {
    let token_str = token.to_string();
    let n: i64 = token_str.parse().unwrap_or_else(|err| {
        emit_error!(token.span(), "invalid number literal ({})", err);
    });
    let n = if negative { n * -1 } else { n };
    (Syntax::Int(n), token.span())
}

fn parse_negative_int<T>(token: TokenTree, tokens: &mut T) -> (Syntax, Span)
where
    T: Iterator<Item = TokenTree>,
{
    let fail = || {
        #[allow(unused_variables)]
        let span = token.span();
        emit_error!(
            span,
            "expected negative sign to be followed by number literal"
        );
    };

    let maybe_token = tokens.next();

    if let Some(token) = maybe_token {
        if let Literal(_) = token {
            parse_int(token, true)
        } else {
            fail()
        }
    } else {
        fail()
    }
}

fn opcode_from_str(s: &str) -> Result<Opcode, ()> {
    use bitcoin::opcodes::{all::*, *};
    match s {
        "OP_0" => Ok(OP_0),
        "OP_TRUE" | "TRUE" => Ok(OP_TRUE),
        "OP_FALSE" | "FALSE" => Ok(OP_FALSE),
        "OP_NOP2" | "NOP2" => Ok(OP_NOP2),
        "OP_NOP3" | "NOP3" => Ok(OP_NOP3),
        "OP_1" => Ok(OP_PUSHNUM_1),
        "OP_2" => Ok(OP_PUSHNUM_2),
        "OP_3" => Ok(OP_PUSHNUM_3),
        "OP_4" => Ok(OP_PUSHNUM_4),
        "OP_5" => Ok(OP_PUSHNUM_5),
        "OP_6" => Ok(OP_PUSHNUM_6),
        "OP_7" => Ok(OP_PUSHNUM_7),
        "OP_8" => Ok(OP_PUSHNUM_8),
        "OP_9" => Ok(OP_PUSHNUM_9),
        "OP_10" => Ok(OP_PUSHNUM_10),
        "OP_11" => Ok(OP_PUSHNUM_11),
        "OP_12" => Ok(OP_PUSHNUM_12),
        "OP_13" => Ok(OP_PUSHNUM_13),
        "OP_14" => Ok(OP_PUSHNUM_14),
        "OP_15" => Ok(OP_PUSHNUM_15),
        "OP_16" => Ok(OP_PUSHNUM_16),
        "OP_PUSHBYTES_0" => Ok(OP_PUSHBYTES_0),
        "OP_PUSHBYTES_1" => Ok(OP_PUSHBYTES_1),
        "OP_PUSHBYTES_2" => Ok(OP_PUSHBYTES_2),
        "OP_PUSHBYTES_3" => Ok(OP_PUSHBYTES_3),
        "OP_PUSHBYTES_4" => Ok(OP_PUSHBYTES_4),
        "OP_PUSHBYTES_5" => Ok(OP_PUSHBYTES_5),
        "OP_PUSHBYTES_6" => Ok(OP_PUSHBYTES_6),
        "OP_PUSHBYTES_7" => Ok(OP_PUSHBYTES_7),
        "OP_PUSHBYTES_8" => Ok(OP_PUSHBYTES_8),
        "OP_PUSHBYTES_9" => Ok(OP_PUSHBYTES_9),
        "OP_PUSHBYTES_10" => Ok(OP_PUSHBYTES_10),
        "OP_PUSHBYTES_11" => Ok(OP_PUSHBYTES_11),
        "OP_PUSHBYTES_12" => Ok(OP_PUSHBYTES_12),
        "OP_PUSHBYTES_13" => Ok(OP_PUSHBYTES_13),
        "OP_PUSHBYTES_14" => Ok(OP_PUSHBYTES_14),
        "OP_PUSHBYTES_15" => Ok(OP_PUSHBYTES_15),
        "OP_PUSHBYTES_16" => Ok(OP_PUSHBYTES_16),
        "OP_PUSHBYTES_17" => Ok(OP_PUSHBYTES_17),
        "OP_PUSHBYTES_18" => Ok(OP_PUSHBYTES_18),
        "OP_PUSHBYTES_19" => Ok(OP_PUSHBYTES_19),
        "OP_PUSHBYTES_20" => Ok(OP_PUSHBYTES_20),
        "OP_PUSHBYTES_21" => Ok(OP_PUSHBYTES_21),
        "OP_PUSHBYTES_22" => Ok(OP_PUSHBYTES_22),
        "OP_PUSHBYTES_23" => Ok(OP_PUSHBYTES_23),
        "OP_PUSHBYTES_24" => Ok(OP_PUSHBYTES_24),
        "OP_PUSHBYTES_25" => Ok(OP_PUSHBYTES_25),
        "OP_PUSHBYTES_26" => Ok(OP_PUSHBYTES_26),
        "OP_PUSHBYTES_27" => Ok(OP_PUSHBYTES_27),
        "OP_PUSHBYTES_28" => Ok(OP_PUSHBYTES_28),
        "OP_PUSHBYTES_29" => Ok(OP_PUSHBYTES_29),
        "OP_PUSHBYTES_30" => Ok(OP_PUSHBYTES_30),
        "OP_PUSHBYTES_31" => Ok(OP_PUSHBYTES_31),
        "OP_PUSHBYTES_32" => Ok(OP_PUSHBYTES_32),
        "OP_PUSHBYTES_33" => Ok(OP_PUSHBYTES_33),
        "OP_PUSHBYTES_34" => Ok(OP_PUSHBYTES_34),
        "OP_PUSHBYTES_35" => Ok(OP_PUSHBYTES_35),
        "OP_PUSHBYTES_36" => Ok(OP_PUSHBYTES_36),
        "OP_PUSHBYTES_37" => Ok(OP_PUSHBYTES_37),
        "OP_PUSHBYTES_38" => Ok(OP_PUSHBYTES_38),
        "OP_PUSHBYTES_39" => Ok(OP_PUSHBYTES_39),
        "OP_PUSHBYTES_40" => Ok(OP_PUSHBYTES_40),
        "OP_PUSHBYTES_41" => Ok(OP_PUSHBYTES_41),
        "OP_PUSHBYTES_42" => Ok(OP_PUSHBYTES_42),
        "OP_PUSHBYTES_43" => Ok(OP_PUSHBYTES_43),
        "OP_PUSHBYTES_44" => Ok(OP_PUSHBYTES_44),
        "OP_PUSHBYTES_45" => Ok(OP_PUSHBYTES_45),
        "OP_PUSHBYTES_46" => Ok(OP_PUSHBYTES_46),
        "OP_PUSHBYTES_47" => Ok(OP_PUSHBYTES_47),
        "OP_PUSHBYTES_48" => Ok(OP_PUSHBYTES_48),
        "OP_PUSHBYTES_49" => Ok(OP_PUSHBYTES_49),
        "OP_PUSHBYTES_50" => Ok(OP_PUSHBYTES_50),
        "OP_PUSHBYTES_51" => Ok(OP_PUSHBYTES_51),
        "OP_PUSHBYTES_52" => Ok(OP_PUSHBYTES_52),
        "OP_PUSHBYTES_53" => Ok(OP_PUSHBYTES_53),
        "OP_PUSHBYTES_54" => Ok(OP_PUSHBYTES_54),
        "OP_PUSHBYTES_55" => Ok(OP_PUSHBYTES_55),
        "OP_PUSHBYTES_56" => Ok(OP_PUSHBYTES_56),
        "OP_PUSHBYTES_57" => Ok(OP_PUSHBYTES_57),
        "OP_PUSHBYTES_58" => Ok(OP_PUSHBYTES_58),
        "OP_PUSHBYTES_59" => Ok(OP_PUSHBYTES_59),
        "OP_PUSHBYTES_60" => Ok(OP_PUSHBYTES_60),
        "OP_PUSHBYTES_61" => Ok(OP_PUSHBYTES_61),
        "OP_PUSHBYTES_62" => Ok(OP_PUSHBYTES_62),
        "OP_PUSHBYTES_63" => Ok(OP_PUSHBYTES_63),
        "OP_PUSHBYTES_64" => Ok(OP_PUSHBYTES_64),
        "OP_PUSHBYTES_65" => Ok(OP_PUSHBYTES_65),
        "OP_PUSHBYTES_66" => Ok(OP_PUSHBYTES_66),
        "OP_PUSHBYTES_67" => Ok(OP_PUSHBYTES_67),
        "OP_PUSHBYTES_68" => Ok(OP_PUSHBYTES_68),
        "OP_PUSHBYTES_69" => Ok(OP_PUSHBYTES_69),
        "OP_PUSHBYTES_70" => Ok(OP_PUSHBYTES_70),
        "OP_PUSHBYTES_71" => Ok(OP_PUSHBYTES_71),
        "OP_PUSHBYTES_72" => Ok(OP_PUSHBYTES_72),
        "OP_PUSHBYTES_73" => Ok(OP_PUSHBYTES_73),
        "OP_PUSHBYTES_74" => Ok(OP_PUSHBYTES_74),
        "OP_PUSHBYTES_75" => Ok(OP_PUSHBYTES_75),
        "OP_PUSHDATA1" => Ok(OP_PUSHDATA1),
        "OP_PUSHDATA2" => Ok(OP_PUSHDATA2),
        "OP_PUSHDATA4" => Ok(OP_PUSHDATA4),
        "OP_PUSHNUM_NEG1" => Ok(OP_PUSHNUM_NEG1),
        "OP_RESERVED" => Ok(OP_RESERVED),
        "OP_PUSHNUM_1" => Ok(OP_PUSHNUM_1),
        "OP_PUSHNUM_2" => Ok(OP_PUSHNUM_2),
        "OP_PUSHNUM_3" => Ok(OP_PUSHNUM_3),
        "OP_PUSHNUM_4" => Ok(OP_PUSHNUM_4),
        "OP_PUSHNUM_5" => Ok(OP_PUSHNUM_5),
        "OP_PUSHNUM_6" => Ok(OP_PUSHNUM_6),
        "OP_PUSHNUM_7" => Ok(OP_PUSHNUM_7),
        "OP_PUSHNUM_8" => Ok(OP_PUSHNUM_8),
        "OP_PUSHNUM_9" => Ok(OP_PUSHNUM_9),
        "OP_PUSHNUM_10" => Ok(OP_PUSHNUM_10),
        "OP_PUSHNUM_11" => Ok(OP_PUSHNUM_11),
        "OP_PUSHNUM_12" => Ok(OP_PUSHNUM_12),
        "OP_PUSHNUM_13" => Ok(OP_PUSHNUM_13),
        "OP_PUSHNUM_14" => Ok(OP_PUSHNUM_14),
        "OP_PUSHNUM_15" => Ok(OP_PUSHNUM_15),
        "OP_PUSHNUM_16" => Ok(OP_PUSHNUM_16),
        "OP_NOP" => Ok(OP_NOP),
        "OP_VER" => Ok(OP_VER),
        "OP_IF" => Ok(OP_IF),
        "OP_NOTIF" => Ok(OP_NOTIF),
        "OP_VERIF" => Ok(OP_VERIF),
        "OP_VERNOTIF" => Ok(OP_VERNOTIF),
        "OP_ELSE" => Ok(OP_ELSE),
        "OP_ENDIF" => Ok(OP_ENDIF),
        "OP_VERIFY" => Ok(OP_VERIFY),
        "OP_RETURN" => Ok(OP_RETURN),
        "OP_TOALTSTACK" => Ok(OP_TOALTSTACK),
        "OP_FROMALTSTACK" => Ok(OP_FROMALTSTACK),
        "OP_2DROP" => Ok(OP_2DROP),
        "OP_2DUP" => Ok(OP_2DUP),
        "OP_3DUP" => Ok(OP_3DUP),
        "OP_2OVER" => Ok(OP_2OVER),
        "OP_2ROT" => Ok(OP_2ROT),
        "OP_2SWAP" => Ok(OP_2SWAP),
        "OP_IFDUP" => Ok(OP_IFDUP),
        "OP_DEPTH" => Ok(OP_DEPTH),
        "OP_DROP" => Ok(OP_DROP),
        "OP_DUP" => Ok(OP_DUP),
        "OP_NIP" => Ok(OP_NIP),
        "OP_OVER" => Ok(OP_OVER),
        "OP_PICK" => Ok(OP_PICK),
        "OP_ROLL" => Ok(OP_ROLL),
        "OP_ROT" => Ok(OP_ROT),
        "OP_SWAP" => Ok(OP_SWAP),
        "OP_TUCK" => Ok(OP_TUCK),
        "OP_CAT" => Ok(OP_CAT),
        "OP_SUBSTR" => Ok(OP_SUBSTR),
        "OP_LEFT" => Ok(OP_LEFT),
        "OP_RIGHT" => Ok(OP_RIGHT),
        "OP_SIZE" => Ok(OP_SIZE),
        "OP_INVERT" => Ok(OP_INVERT),
        "OP_AND" => Ok(OP_AND),
        "OP_OR" => Ok(OP_OR),
        "OP_XOR" => Ok(OP_XOR),
        "OP_EQUAL" => Ok(OP_EQUAL),
        "OP_EQUALVERIFY" => Ok(OP_EQUALVERIFY),
        "OP_RESERVED1" => Ok(OP_RESERVED1),
        "OP_RESERVED2" => Ok(OP_RESERVED2),
        "OP_1ADD" => Ok(OP_1ADD),
        "OP_1SUB" => Ok(OP_1SUB),
        "OP_2MUL" => Ok(OP_2MUL),
        "OP_2DIV" => Ok(OP_2DIV),
        "OP_NEGATE" => Ok(OP_NEGATE),
        "OP_ABS" => Ok(OP_ABS),
        "OP_NOT" => Ok(OP_NOT),
        "OP_0NOTEQUAL" => Ok(OP_0NOTEQUAL),
        "OP_ADD" => Ok(OP_ADD),
        "OP_SUB" => Ok(OP_SUB),
        "OP_MUL" => Ok(OP_MUL),
        "OP_DIV" => Ok(OP_DIV),
        "OP_MOD" => Ok(OP_MOD),
        "OP_LSHIFT" => Ok(OP_LSHIFT),
        "OP_RSHIFT" => Ok(OP_RSHIFT),
        "OP_BOOLAND" => Ok(OP_BOOLAND),
        "OP_BOOLOR" => Ok(OP_BOOLOR),
        "OP_NUMEQUAL" => Ok(OP_NUMEQUAL),
        "OP_NUMEQUALVERIFY" => Ok(OP_NUMEQUALVERIFY),
        "OP_NUMNOTEQUAL" => Ok(OP_NUMNOTEQUAL),
        "OP_LESSTHAN" => Ok(OP_LESSTHAN),
        "OP_GREATERTHAN" => Ok(OP_GREATERTHAN),
        "OP_LESSTHANOREQUAL" => Ok(OP_LESSTHANOREQUAL),
        "OP_GREATERTHANOREQUAL" => Ok(OP_GREATERTHANOREQUAL),
        "OP_MIN" => Ok(OP_MIN),
        "OP_MAX" => Ok(OP_MAX),
        "OP_WITHIN" => Ok(OP_WITHIN),
        "OP_RIPEMD160" => Ok(OP_RIPEMD160),
        "OP_SHA1" => Ok(OP_SHA1),
        "OP_SHA256" => Ok(OP_SHA256),
        "OP_HASH160" => Ok(OP_HASH160),
        "OP_HASH256" => Ok(OP_HASH256),
        "OP_CODESEPARATOR" => Ok(OP_CODESEPARATOR),
        "OP_CHECKSIG" => Ok(OP_CHECKSIG),
        "OP_CHECKSIGVERIFY" => Ok(OP_CHECKSIGVERIFY),
        "OP_CHECKMULTISIG" => Ok(OP_CHECKMULTISIG),
        "OP_CHECKMULTISIGVERIFY" => Ok(OP_CHECKMULTISIGVERIFY),
        "OP_NOP1" => Ok(OP_NOP1),
        "OP_CLTV" => Ok(OP_CLTV),
        "OP_CSV" => Ok(OP_CSV),
        "OP_NOP4" => Ok(OP_NOP4),
        "OP_NOP5" => Ok(OP_NOP5),
        "OP_NOP6" => Ok(OP_NOP6),
        "OP_NOP7" => Ok(OP_NOP7),
        "OP_NOP8" => Ok(OP_NOP8),
        "OP_NOP9" => Ok(OP_NOP9),
        "OP_NOP10" => Ok(OP_NOP10),
        "OP_CHECKSIGADD" => Ok(OP_CHECKSIGADD),
        "OP_RETURN_187" => Ok(OP_RETURN_187),
        "OP_RETURN_188" => Ok(OP_RETURN_188),
        "OP_RETURN_189" => Ok(OP_RETURN_189),
        "OP_RETURN_190" => Ok(OP_RETURN_190),
        "OP_RETURN_191" => Ok(OP_RETURN_191),
        "OP_RETURN_192" => Ok(OP_RETURN_192),
        "OP_RETURN_193" => Ok(OP_RETURN_193),
        "OP_RETURN_194" => Ok(OP_RETURN_194),
        "OP_RETURN_195" => Ok(OP_RETURN_195),
        "OP_RETURN_196" => Ok(OP_RETURN_196),
        "OP_RETURN_197" => Ok(OP_RETURN_197),
        "OP_RETURN_198" => Ok(OP_RETURN_198),
        "OP_RETURN_199" => Ok(OP_RETURN_199),
        "OP_RETURN_200" => Ok(OP_RETURN_200),
        "OP_RETURN_201" => Ok(OP_RETURN_201),
        "OP_RETURN_202" => Ok(OP_RETURN_202),
        "OP_RETURN_203" => Ok(OP_RETURN_203),
        "OP_RETURN_204" => Ok(OP_RETURN_204),
        "OP_RETURN_205" => Ok(OP_RETURN_205),
        "OP_RETURN_206" => Ok(OP_RETURN_206),
        "OP_RETURN_207" => Ok(OP_RETURN_207),
        "OP_RETURN_208" => Ok(OP_RETURN_208),
        "OP_RETURN_209" => Ok(OP_RETURN_209),
        "OP_RETURN_210" => Ok(OP_RETURN_210),
        "OP_RETURN_211" => Ok(OP_RETURN_211),
        "OP_RETURN_212" => Ok(OP_RETURN_212),
        "OP_RETURN_213" => Ok(OP_RETURN_213),
        "OP_RETURN_214" => Ok(OP_RETURN_214),
        "OP_RETURN_215" => Ok(OP_RETURN_215),
        "OP_RETURN_216" => Ok(OP_RETURN_216),
        "OP_RETURN_217" => Ok(OP_RETURN_217),
        "OP_RETURN_218" => Ok(OP_RETURN_218),
        "OP_RETURN_219" => Ok(OP_RETURN_219),
        "OP_RETURN_220" => Ok(OP_RETURN_220),
        "OP_RETURN_221" => Ok(OP_RETURN_221),
        "OP_RETURN_222" => Ok(OP_RETURN_222),
        "OP_RETURN_223" => Ok(OP_RETURN_223),
        "OP_RETURN_224" => Ok(OP_RETURN_224),
        "OP_RETURN_225" => Ok(OP_RETURN_225),
        "OP_RETURN_226" => Ok(OP_RETURN_226),
        "OP_RETURN_227" => Ok(OP_RETURN_227),
        "OP_RETURN_228" => Ok(OP_RETURN_228),
        "OP_RETURN_229" => Ok(OP_RETURN_229),
        "OP_RETURN_230" => Ok(OP_RETURN_230),
        "OP_RETURN_231" => Ok(OP_RETURN_231),
        "OP_RETURN_232" => Ok(OP_RETURN_232),
        "OP_RETURN_233" => Ok(OP_RETURN_233),
        "OP_RETURN_234" => Ok(OP_RETURN_234),
        "OP_RETURN_235" => Ok(OP_RETURN_235),
        "OP_RETURN_236" => Ok(OP_RETURN_236),
        "OP_RETURN_237" => Ok(OP_RETURN_237),
        "OP_RETURN_238" => Ok(OP_RETURN_238),
        "OP_RETURN_239" => Ok(OP_RETURN_239),
        "OP_RETURN_240" => Ok(OP_RETURN_240),
        "OP_RETURN_241" => Ok(OP_RETURN_241),
        "OP_RETURN_242" => Ok(OP_RETURN_242),
        "OP_RETURN_243" => Ok(OP_RETURN_243),
        "OP_RETURN_244" => Ok(OP_RETURN_244),
        "OP_RETURN_245" => Ok(OP_RETURN_245),
        "OP_RETURN_246" => Ok(OP_RETURN_246),
        "OP_RETURN_247" => Ok(OP_RETURN_247),
        "OP_RETURN_248" => Ok(OP_RETURN_248),
        "OP_RETURN_249" => Ok(OP_RETURN_249),
        "OP_RETURN_250" => Ok(OP_RETURN_250),
        "OP_RETURN_251" => Ok(OP_RETURN_251),
        "OP_RETURN_252" => Ok(OP_RETURN_252),
        "OP_RETURN_253" => Ok(OP_RETURN_253),
        "OP_RETURN_254" => Ok(OP_RETURN_254),
        "OP_INVALIDOPCODE" => Ok(OP_INVALIDOPCODE),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::opcodes::all as opcodes;
    use quote::quote;

    #[test]
    fn parse_empty() {
        assert!(parse(quote!()).is_empty());
    }

    #[test]
    #[should_panic(expected = "unexpected token")]
    fn parse_unexpected_token() {
        parse(quote!(OP_CHECKSIG &));
    }

    //#[test]
    //#[should_panic(expected = "unknown opcode \"A\"")]
    //fn parse_invalid_opcode() {
    //    parse(quote!(OP_CHECKSIG A B));
    //}

    #[test]
    fn parse_opcodes() {
        let syntax = parse(quote!(OP_CHECKSIG OP_HASH160));

        if let Syntax::Opcode(opcode) = syntax[0].0 {
            assert_eq!(opcode, opcodes::OP_CHECKSIG);
        } else {
            panic!();
        }

        if let Syntax::Opcode(opcode) = syntax[1].0 {
            assert_eq!(opcode, opcodes::OP_HASH160);
        } else {
            panic!();
        }
    }

    #[test]
    #[should_panic(expected = "unterminated escape")]
    fn parse_unterminated_escape() {
        parse(quote!(OP_CHECKSIG < abc));
    }

    #[test]
    fn parse_escape() {
        let syntax = parse(quote!(OP_CHECKSIG<abc>));

        if let Syntax::Escape(tokens) = &syntax[1].0 {
            let tokens = tokens.clone().into_iter().collect::<Vec<TokenTree>>();

            assert_eq!(tokens.len(), 1);
            if let TokenTree::Ident(_) = tokens[0] {
                assert_eq!(tokens[0].to_string(), "abc");
            } else {
                panic!()
            }
        } else {
            panic!()
        }
    }

    #[test]
    #[should_panic(expected = "invalid number literal (invalid digit found in string)")]
    fn parse_invalid_int() {
        parse(quote!(OP_CHECKSIG 12g34));
    }

    #[test]
    fn parse_int() {
        let syntax = parse(quote!(OP_CHECKSIG 1234));

        if let Syntax::Int(n) = syntax[1].0 {
            assert_eq!(n, 1234i64);
        } else {
            panic!()
        }
    }

    #[test]
    #[should_panic(expected = "expected negative sign to be followed by number literal")]
    fn parse_invalid_negative_sign() {
        parse(quote!(OP_CHECKSIG - OP_HASH160));
    }

    #[test]
    fn parse_negative_int() {
        let syntax = parse(quote!(OP_CHECKSIG - 1234));

        if let Syntax::Int(n) = syntax[1].0 {
            assert_eq!(n, -1234i64);
        } else {
            panic!()
        }
    }

    #[test]
    fn parse_hex() {
        let syntax = parse(quote!(OP_CHECKSIG 0x123456789abcde));

        if let Syntax::Bytes(bytes) = &syntax[1].0 {
            assert_eq!(bytes, &vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde]);
        } else {
            panic!("Unable to cast Syntax as Syntax::Bytes")
        }
    }
}
